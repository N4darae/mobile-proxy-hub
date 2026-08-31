package rotate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n4darae/huawei-API/src/internal/device"
	"github.com/n4darae/huawei-API/src/internal/device/sim"
	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/eventbus"
	"github.com/n4darae/huawei-API/src/internal/fw"
	"github.com/n4darae/huawei-API/src/internal/secrets"
	"github.com/n4darae/huawei-API/src/internal/store"
)

var (
	testNodeIP  = netip.MustParseAddr("139.99.68.39")
	testBaseNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
)

type simClock struct{ farm *sim.Farm }

func (c *simClock) Now() time.Time { return c.farm.Now() }

func (c *simClock) Since(t time.Time) time.Duration { return c.Now().Sub(t) }

func (c *simClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.farm.Advance(d)
	ch <- c.farm.Now()
	return ch
}

func (c *simClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.farm.Advance(d)
	return nil
}

type recFW struct {
	mu           sync.Mutex
	calls        []string
	fenced       map[string]bool
	live         int
	maxLive      int
	failFence    error
	unknownIface bool
	notImpl      bool
}

var _ fw.Firewall = (*recFW)(nil)

func newRecFW() *recFW { return &recFW{fenced: map[string]bool{}} }

func (f *recFW) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *recFW) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *recFW) MaxLive() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxLive
}

func (f *recFW) EnsureTable(context.Context) error { return nil }

func (f *recFW) Verify(context.Context) error { return nil }

func (f *recFW) AddPublic(context.Context, string, netip.Addr) error { return nil }

func (f *recFW) RemovePublic(context.Context, string, netip.Addr) error { return nil }

func (f *recFW) AddDongle(context.Context, string, netip.Addr) error { return nil }

func (f *recFW) RemoveDongle(context.Context, string) error { return nil }

func (f *recFW) Fence(_ context.Context, iface string) error {
	f.record("fence:" + iface)
	f.mu.Lock()
	err := f.failFence
	if err == nil {
		f.fenced[iface] = true
		f.live++
		if f.live > f.maxLive {
			f.maxLive = f.live
		}
	}
	f.mu.Unlock()
	return err
}

func (f *recFW) Unfence(_ context.Context, iface string) error {
	f.record("unfence:" + iface)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unknownIface {
		return fmt.Errorf("%w: %s", fw.ErrUnknownIface, iface)
	}
	if f.fenced[iface] {
		f.fenced[iface] = false
		f.live--
	}
	return nil
}

func (f *recFW) IsFenced(_ context.Context, iface string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unknownIface {
		return false, fmt.Errorf("%w: %s", fw.ErrUnknownIface, iface)
	}
	return f.fenced[iface], nil
}

func (f *recFW) KillSockets(_ context.Context, src netip.Addr) (int, error) {
	f.record("kill:" + src.String())
	if f.notImpl {
		return 0, domain.ErrNotImplemented
	}
	return 3, nil
}

func (f *recFW) FlushConntrack(_ context.Context, src netip.Addr) (int, error) {
	f.record("flush:" + src.String())
	if f.notImpl {
		return 0, domain.ErrNotImplemented
	}
	return 5, nil
}

func (f *recFW) CustomerAcceptHits(context.Context) (uint64, error) { return 0, nil }

type simProber struct {
	farm *sim.Farm

	mu        sync.Mutex
	leak      netip.Addr
	leakAfter int
	fail      error
	gate      chan struct{}
	sourceN   int
	socksN    int
	httpN     int
	inflight  atomic.Int32
	maxFlight atomic.Int32
}

var _ Prober = (*simProber)(nil)

func newSimProber(f *sim.Farm) *simProber { return &simProber{farm: f} }

func (p *simProber) setLeak(a netip.Addr) {
	p.mu.Lock()
	p.leak = a
	p.mu.Unlock()
}

func (p *simProber) setLeakAfter(a netip.Addr, calls int) {
	p.mu.Lock()
	p.leak = a
	p.leakAfter = calls
	p.mu.Unlock()
}

func (p *simProber) sourceCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sourceN
}

func (p *simProber) setGate(c chan struct{}) {
	p.mu.Lock()
	p.gate = c
	p.mu.Unlock()
}

func (p *simProber) ProbeSource(ctx context.Context, src netip.Addr) (EgressProbe, error) {
	p.mu.Lock()
	p.sourceN++
	leak, fail, gate := p.leak, p.fail, p.gate
	if p.sourceN <= p.leakAfter {
		leak = netip.Addr{}
	}
	p.mu.Unlock()

	n := p.inflight.Add(1)
	for {
		m := p.maxFlight.Load()
		if n <= m || p.maxFlight.CompareAndSwap(m, n) {
			break
		}
	}
	defer p.inflight.Add(-1)

	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return EgressProbe{}, ctx.Err()
		}
	}
	if fail != nil {
		return EgressProbe{}, fail
	}
	if leak.IsValid() {
		return EgressProbe{IP: leak, LatencyMS: 7, Echo: "leak"}, nil
	}

	slot, ok := slotOfSource(src)
	if !ok {
		return EgressProbe{}, fmt.Errorf("%w: no slot owns source %s", ErrProbeFailed, src)
	}
	d := p.farm.Device(slot)
	if d == nil {
		return EgressProbe{}, fmt.Errorf("%w: slot %d is not simulated", ErrProbeFailed, int(slot))
	}
	if d.ConnectionStatus() != device.ConnConnected {
		return EgressProbe{}, fmt.Errorf("%w: slot %d has no data session", ErrProbeFailed, int(slot))
	}
	return EgressProbe{IP: d.PublicIP(), LatencyMS: 11, Echo: "sim"}, nil
}

func (p *simProber) ProbeSocks(ctx context.Context, ep Endpoint) (EgressProbe, error) {
	p.mu.Lock()
	p.socksN++
	p.mu.Unlock()
	return p.viaProxy(ctx, ep)
}

func (p *simProber) ProbeHTTP(ctx context.Context, ep Endpoint) (EgressProbe, error) {
	p.mu.Lock()
	p.httpN++
	p.mu.Unlock()
	return p.viaProxy(ctx, ep)
}

func (p *simProber) viaProxy(ctx context.Context, ep Endpoint) (EgressProbe, error) {
	slot := domain.Slot(ep.Addr.Port() % 1000)
	return p.ProbeSource(ctx, slot.HostIP())
}

func slotOfSource(a netip.Addr) (domain.Slot, bool) {
	if !a.Is4() {
		return 0, false
	}
	b := a.As4()
	s := domain.Slot(int(b[2]) - domain.SubnetOctetBase)
	return s, s.Valid()
}

type stubRebooter struct {
	mu     sync.Mutex
	calls  []string
	opID   string
	err    error
	repos  store.Repos
	clock  domain.Clock
	nextID int
}

func (r *stubRebooter) RebootAuto(ctx context.Context, dongleID, reason string) (domain.Operation, error) {
	r.mu.Lock()
	r.calls = append(r.calls, dongleID+":"+reason)
	r.nextID++
	id := r.opID
	if id == "" {
		id = "op_reboot_" + strconv.Itoa(r.nextID)
	}
	err := r.err
	r.mu.Unlock()
	if err != nil {
		return domain.Operation{}, err
	}
	now := r.clock.Now()
	op := domain.Operation{
		ID:          id,
		Kind:        domain.OpReboot,
		SubjectType: domain.SubjectDongle,
		SubjectID:   dongleID,
		State:       domain.OpPending,
		StartedAt:   domain.UnixMillis(now),
		DeadlineAt:  domain.UnixMillis(now.Add(5 * time.Minute)),
		Trigger:     domain.TriggerAutoRecovery,
		ActorType:   domain.ActorSystem,
		ActorID:     reason,
	}
	if r.repos != nil {
		if err := r.repos.Operations().Create(ctx, op); err != nil {
			return domain.Operation{}, err
		}
	}
	return op, nil
}

func (r *stubRebooter) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

type harness struct {
	t     *testing.T
	farm  *sim.Farm
	clock *simClock
	db    *store.Store
	fw    *recFW
	probe *simProber
	bus   *eventbus.MemBus
	sink  *eventSink
	boot  *stubRebooter
	eng   *Engine
	node  domain.Node
	pol   Policy
}

type harnessOptions struct {
	Slots       int
	HoldToNewIP time.Duration
	Policy      *Policy
	NoRebooter  bool
	HoldFails   error
}

type holdFailClock struct {
	*simClock
	hold time.Duration
	err  error
}

func (c *holdFailClock) Sleep(ctx context.Context, d time.Duration) error {
	if d == c.hold {
		return c.err
	}
	return c.simClock.Sleep(ctx, d)
}

func testPolicy() Policy {
	p := DefaultPolicy()
	p.Jitter = 0
	p.MinInterval = 0
	return p
}

func newHarness(t *testing.T, o harnessOptions) *harness {
	t.Helper()
	if o.Slots <= 0 {
		o.Slots = 1
	}
	base := testBaseNow
	farm := sim.NewFarm(o.Slots, sim.FarmOptions{
		HoldToNewIP: o.HoldToNewIP,
		Clock:       func() time.Time { return base },
	})
	t.Cleanup(func() { farm.Close() })

	clock := &simClock{farm: farm}
	kek, err := secrets.GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	sealer, err := secrets.NewSealer(kek)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "state", "dongled.db"), sealer, store.WithClock(clock))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	ctx := context.Background()
	node := domain.Node{ID: "n1", Name: "local", Kind: domain.NodeKindLocal, PublicHost: testNodeIP}
	if err := db.Nodes().Upsert(ctx, node); err != nil {
		t.Fatalf("Upsert node: %v", err)
	}
	for i := 1; i <= o.Slots; i++ {
		slot := domain.Slot(i)
		row := domain.SlotRow{
			ID:      slotID(slot),
			NodeID:  node.ID,
			Slot:    slot,
			USBPath: "1-13." + slot.String(),
			IDPath:  "pci-0000:00:14.0-usb-0:13." + slot.String() + ":1.0",
			IfName:  slot.IfaceName(),
		}
		if err := db.Slots().Create(ctx, row); err != nil {
			t.Fatalf("Create slot %d: %v", i, err)
		}
		d := domain.Dongle{
			ID:                 dongleID(slot),
			NodeID:             node.ID,
			IMEI:               "86182103247950" + slot.String(),
			Carrier:            "beeline",
			AutoRecoverEnabled: true,
		}
		if err := db.Dongles().Create(ctx, d); err != nil {
			t.Fatalf("Create dongle %d: %v", i, err)
		}
		if err := db.Slots().Attach(ctx, row.ID, d.ID); err != nil {
			t.Fatalf("Attach dongle %d: %v", i, err)
		}
		px := domain.Proxy{
			ID:        proxyID(slot),
			SlotID:    row.ID,
			Enabled:   true,
			SocksPort: slot.SocksPort(),
			HTTPPort:  slot.HTTPPort(),
			Username:  "cust_" + slot.String(),
			Password:  "Kq7mZr2xTn9wLb4V",
			AuthMode:  domain.AuthUserPass,
			Policy:    domain.DefaultProxyPolicy(),
		}
		if err := db.Proxies().Create(ctx, px); err != nil {
			t.Fatalf("Create proxy %d: %v", i, err)
		}
		dev, err := farm.Registry().ForSlot(ctx, slot)
		if err != nil {
			t.Fatalf("registry slot %d: %v", i, err)
		}
		if err := dev.DataSwitch(ctx, true); err != nil {
			t.Fatalf("initial data on for slot %d: %v", i, err)
		}
	}

	pol := testPolicy()
	if o.Policy != nil {
		pol = *o.Policy
	}
	h := &harness{
		t:     t,
		farm:  farm,
		clock: clock,
		db:    db,
		fw:    newRecFW(),
		probe: newSimProber(farm),
		bus:   eventbus.NewMemBus(256),
		node:  node,
		pol:   pol,
	}
	if !o.NoRebooter {
		h.boot = &stubRebooter{repos: db, clock: clock}
	}
	var engClock domain.Clock = clock
	if o.HoldFails != nil {
		engClock = &holdFailClock{simClock: clock, hold: pol.HoldFor(1), err: o.HoldFails}
	}
	deps := Deps{
		Repos:  db,
		Dev:    farm.Registry(),
		FW:     h.fw,
		Probe:  h.probe,
		Bus:    h.bus,
		Clock:  engClock,
		Policy: pol,
		NodeID: node.ID,
		Rand:   func() float64 { return 0 },
	}
	if h.boot != nil {
		deps.Reboot = h.boot
	}
	h.sink = newEventSink(t, h.bus)
	eng, err := New(deps)
	if err != nil {
		t.Fatalf("rotate.New: %v", err)
	}
	h.eng = eng
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = eng.Shutdown(c)
	})
	return h
}

func slotID(s domain.Slot) string { return "s" + s.String() }

func dongleID(s domain.Slot) string { return "d" + s.String() }

func proxyID(s domain.Slot) string { return "p" + s.String() }

func (h *harness) rotate(req Request) (domain.Operation, error) {
	h.t.Helper()
	ctx := context.Background()
	op, err := h.eng.Rotate(ctx, req)
	if err != nil {
		return domain.Operation{}, err
	}
	wait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return h.eng.Wait(wait, op.ID)
}

type eventSink struct {
	mu     sync.Mutex
	events []eventbus.Event
	stop   func()
	done   chan struct{}
}

func newEventSink(t *testing.T, bus *eventbus.MemBus) *eventSink {
	t.Helper()
	ch, cancel, err := bus.Subscribe(context.Background(), []string{eventbus.TopicAll})
	if err != nil {
		t.Fatalf("bus subscribe: %v", err)
	}
	s := &eventSink{stop: cancel, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		for e := range ch {
			s.mu.Lock()
			s.events = append(s.events, e)
			s.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-s.done
	})
	return s
}

func (s *eventSink) Events() []eventbus.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]eventbus.Event(nil), s.events...)
}

func (s *eventSink) waitUntil(t *testing.T, want func([]eventbus.Event) bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if want(s.Events()) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the event bus never carried what the test was waiting for")
}

func (h *harness) steps(subject string) []string {
	h.t.Helper()
	h.sink.waitUntil(h.t, func(evs []eventbus.Event) bool {
		for _, e := range evs {
			if e.Type != eventbus.EvOpDone {
				continue
			}
			var p opPayload
			if err := json.Unmarshal(e.Data, &p); err == nil && p.SubjectID == subject {
				return true
			}
		}
		return false
	})
	out := []string{}
	for _, e := range h.sink.Events() {
		if e.Type != eventbus.EvOpUpdate && e.Type != eventbus.EvOpDone {
			continue
		}
		var p opPayload
		if err := json.Unmarshal(e.Data, &p); err != nil {
			continue
		}
		if subject != "" && p.SubjectID != subject {
			continue
		}
		if p.Step == "" {
			continue
		}
		if len(out) > 0 && out[len(out)-1] == p.Step {
			continue
		}
		out = append(out, p.Step)
	}
	return out
}

func (h *harness) lastRotation(proxy string) domain.Rotation {
	h.t.Helper()
	r, err := h.db.Rotations().LastFor(context.Background(), proxy)
	if err != nil {
		h.t.Fatalf("LastFor %s: %v", proxy, err)
	}
	return r
}

func (h *harness) result(op domain.Operation) OpResult {
	h.t.Helper()
	var out OpResult
	if op.ResultJSON == "" {
		return out
	}
	if err := json.Unmarshal([]byte(op.ResultJSON), &out); err != nil {
		h.t.Fatalf("result json %q: %v", op.ResultJSON, err)
	}
	return out
}

func (h *harness) device(s domain.Slot) device.Device {
	h.t.Helper()
	d, err := h.farm.Registry().ForSlot(context.Background(), s)
	if err != nil {
		h.t.Fatalf("device %d: %v", int(s), err)
	}
	return d
}
