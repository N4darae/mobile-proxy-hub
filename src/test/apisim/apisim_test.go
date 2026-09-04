package apisim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/n4darae/huawei-API/src/internal/auth"
	"github.com/n4darae/huawei-API/src/internal/device"
	"github.com/n4darae/huawei-API/src/internal/device/sim"
	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/eventbus"
	"github.com/n4darae/huawei-API/src/internal/fw"
	"github.com/n4darae/huawei-API/src/internal/httpapi"
	"github.com/n4darae/huawei-API/src/internal/logging"
	"github.com/n4darae/huawei-API/src/internal/ratelimit"
	"github.com/n4darae/huawei-API/src/internal/rotate"
	"github.com/n4darae/huawei-API/src/internal/secrets"
	"github.com/n4darae/huawei-API/src/internal/store"
)

var nodeHost = netip.MustParseAddr("139.99.68.39")

type farmClock struct{ farm *sim.Farm }

func (c *farmClock) Now() time.Time { return c.farm.Now() }

func (c *farmClock) Since(t time.Time) time.Duration { return c.Now().Sub(t) }

func (c *farmClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.farm.Advance(d)
	ch <- c.farm.Now()
	return ch
}

func (c *farmClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.farm.Advance(d)
	return nil
}

type farmProber struct{ farm *sim.Farm }

func (p *farmProber) ProbeSource(_ context.Context, src netip.Addr) (rotate.EgressProbe, error) {
	slot, ok := slotOfHostIP(src)
	if !ok {
		return rotate.EgressProbe{}, rotate.ErrProbeFailed
	}
	d := p.farm.Device(slot)
	if d == nil || d.ConnectionStatus() != device.ConnConnected {
		return rotate.EgressProbe{}, rotate.ErrProbeFailed
	}
	return rotate.EgressProbe{IP: d.PublicIP(), LatencyMS: 9, Echo: "sim"}, nil
}

func (p *farmProber) ProbeSocks(ctx context.Context, ep rotate.Endpoint) (rotate.EgressProbe, error) {
	return p.viaProxy(ctx, ep)
}

func (p *farmProber) ProbeHTTP(ctx context.Context, ep rotate.Endpoint) (rotate.EgressProbe, error) {
	return p.viaProxy(ctx, ep)
}

func (p *farmProber) viaProxy(ctx context.Context, ep rotate.Endpoint) (rotate.EgressProbe, error) {
	return p.ProbeSource(ctx, domain.Slot(ep.Addr.Port()%1000).HostIP())
}

func slotOfHostIP(a netip.Addr) (domain.Slot, bool) {
	if !a.Is4() {
		return 0, false
	}
	b := a.As4()
	s := domain.Slot(int(b[2]) - domain.SubnetOctetBase)
	return s, s.Valid()
}

type harness struct {
	farm    *sim.Farm
	db      *store.Store
	router  http.Handler
	rotator *rotate.Engine
	secret  string
	proxy   domain.Proxy
}

func (h *harness) awaitOperation(t *testing.T, body []byte) domain.Operation {
	t.Helper()
	var res struct {
		OperationID string `json:"operation_id"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatalf("response is not json: %v (%s)", err, body)
	}
	if res.OperationID == "" {
		t.Fatalf("the accepted rotation carried no operation id: %s", body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	op, err := h.rotator.Wait(ctx, res.OperationID)
	if err != nil {
		t.Fatalf("Wait for %s: %v", res.OperationID, err)
	}
	return op
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	base := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	farm := sim.NewFarm(1, sim.FarmOptions{
		HoldToNewIP: time.Second,
		Clock:       func() time.Time { return base },
	})
	t.Cleanup(func() { _ = farm.Close() })
	clock := &farmClock{farm: farm}

	kek, err := secrets.GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	sealer, err := secrets.NewSealer(kek)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "dongled.db"), sealer, store.WithClock(clock))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := auth.EnsureSchema(ctx, db.DB()); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	node := domain.Node{ID: "n1", Name: "local", Kind: domain.NodeKindLocal, PublicHost: nodeHost}
	if err := db.Nodes().Upsert(ctx, node); err != nil {
		t.Fatalf("Upsert node: %v", err)
	}

	slot := domain.Slot(1)
	row := domain.SlotRow{
		ID:      "s1",
		NodeID:  node.ID,
		Slot:    slot,
		USBPath: "1-13.1",
		IDPath:  "pci-0000:00:14.0-usb-0:13.1:1.0",
		IfName:  slot.IfaceName(),
	}
	if err := db.Slots().Create(ctx, row); err != nil {
		t.Fatalf("Create slot: %v", err)
	}
	dongle := domain.Dongle{ID: "d1", NodeID: node.ID, IMEI: "861821032479501", Carrier: "viettel"}
	if err := db.Dongles().Create(ctx, dongle); err != nil {
		t.Fatalf("Create dongle: %v", err)
	}
	if err := db.Slots().Attach(ctx, row.ID, dongle.ID); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	customer := domain.Customer{ID: "c1", Name: "acme"}
	if err := db.Customers().Create(ctx, customer); err != nil {
		t.Fatalf("Create customer: %v", err)
	}
	proxy := domain.Proxy{
		ID:         "p1",
		SlotID:     row.ID,
		CustomerID: &customer.ID,
		Enabled:    true,
		SocksPort:  slot.SocksPort(),
		HTTPPort:   slot.HTTPPort(),
		Username:   "cust_1",
		Password:   "Kq7mZr2xTn9wLb4V",
		AuthMode:   domain.AuthUserPass,
		Policy:     domain.DefaultProxyPolicy(),
	}
	if err := db.Proxies().Create(ctx, proxy); err != nil {
		t.Fatalf("Create proxy: %v", err)
	}

	dev, err := farm.Registry().ForSlot(ctx, slot)
	if err != nil {
		t.Fatalf("ForSlot: %v", err)
	}
	if err := dev.DataSwitch(ctx, true); err != nil {
		t.Fatalf("initial data on: %v", err)
	}

	pol := rotate.DefaultPolicy()
	pol.Jitter = 0
	pol.MinInterval = 0

	rotator, err := rotate.New(rotate.Deps{
		Repos:  db,
		Dev:    farm.Registry(),
		FW:     fw.NewFake(),
		Probe:  &farmProber{farm: farm},
		Bus:    eventbus.NewMemBus(256),
		Clock:  clock,
		Policy: pol,
		NodeID: node.ID,
		Rand:   func() float64 { return 0 },
	})
	if err != nil {
		t.Fatalf("rotate.New: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = rotator.Shutdown(c)
	})

	keys := auth.NewKeys(db.DB(), clock.Now)
	key, secret, err := keys.Create(ctx, auth.NewKey{
		Name:       "rotate only",
		CustomerID: &customer.ID,
		Scopes:     []string{auth.ScopeRotate},
		ProxyIDs:   []string{proxy.ID},
	})
	if err != nil {
		t.Fatalf("Keys.Create: %v", err)
	}
	if len(key.ProxyIDs) != 1 {
		t.Fatalf("the key must be bound to exactly one proxy, got %v", key.ProxyIDs)
	}

	api, err := httpapi.New(httpapi.Deps{
		NodeID:   node.ID,
		Version:  "test",
		Repos:    db,
		Rotator:  rotator,
		Waiter:   rotator,
		Bus:      eventbus.NewMemBus(256),
		Sessions: auth.NewSessions(db.DB(), time.Hour, clock.Now),
		Keys:     keys,
		Lockout:  auth.NewLockout(db.DB(), auth.DefaultLockoutPolicy(), clock.Now),
		Limiter:  ratelimit.New(ratelimit.DefaultLimit(), clock.Now),
		Clock:    clock,
		Log:      logging.New(os.Stderr, "error"),
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}

	return &harness{
		farm:    farm,
		db:      db,
		router:  httpapi.NewRouter(nil, api),
		rotator: rotator,
		secret:  secret,
		proxy:   proxy,
	}
}

func (h *harness) rotate(t *testing.T, proxyID, secret string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rotate/"+proxyID, nil)
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func TestACustomerKeyRotatesARealSimulatedDongleOverHTTP(t *testing.T) {
	h := newHarness(t)
	dev := h.farm.Device(domain.Slot(1))
	before := dev.PublicIP()

	rec := h.rotate(t, h.proxy.ID, h.secret)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /rotate returned %d, want 202: %s", rec.Code, rec.Body.String())
	}

	op := h.awaitOperation(t, rec.Body.Bytes())
	if op.State != domain.OpSucceeded {
		t.Fatalf("the rotation finished as %q with error %q", op.State, op.Error)
	}

	after := dev.PublicIP()
	if after == before {
		t.Fatalf("the dongle kept public ip %s across a rotation", before)
	}
	if !dev.DataOn() {
		t.Fatalf("the rotation finished with mobile data off")
	}
	if dev.ConnectionStatus() != device.ConnConnected {
		t.Fatalf("connection status is %d after the rotation, want connected", int(dev.ConnectionStatus()))
	}

	rotations, err := h.db.Rotations().List(context.Background(), store.RotationFilter{ProxyID: h.proxy.ID})
	if err != nil {
		t.Fatalf("Rotations.List: %v", err)
	}
	if len(rotations) != 1 {
		t.Fatalf("the store holds %d rotations, want exactly one", len(rotations))
	}
	if rotations[0].Result != domain.RotationChanged {
		t.Fatalf("the recorded rotation is %q, want %q", rotations[0].Result, domain.RotationChanged)
	}
	t.Logf("public ip %s -> %s, recorded as %q", before, after, rotations[0].Result)
}

func TestRotateWithoutAKeyIsRefusedAndLeavesTheDongleAlone(t *testing.T) {
	h := newHarness(t)
	dev := h.farm.Device(domain.Slot(1))
	before := dev.PublicIP()

	if rec := h.rotate(t, h.proxy.ID, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated rotate returned %d, want 401: %s", rec.Code, rec.Body.String())
	}
	if dev.PublicIP() != before {
		t.Fatal("an unauthenticated request still cycled the data session")
	}
}

func TestAKeyCannotRotateAProxyItDoesNotOwn(t *testing.T) {
	h := newHarness(t)
	dev := h.farm.Device(domain.Slot(1))
	before := dev.PublicIP()

	rec := h.rotate(t, "p-someone-else", h.secret)
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("rotating a foreign proxy returned %d, want 403 or 404: %s", rec.Code, rec.Body.String())
	}
	if dev.PublicIP() != before {
		t.Fatal("a request for a foreign proxy still cycled this dongle")
	}
}
