package linux

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/netcfg"
)

type recorder struct {
	mu    sync.Mutex
	calls []string
	fail  func(cmd string) error
}

func (r *recorder) exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	r.mu.Lock()
	r.calls = append(r.calls, cmd)
	fail := r.fail
	r.mu.Unlock()
	if fail != nil {
		return nil, fail(cmd)
	}
	return nil, nil
}

func (r *recorder) contains(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func (r *recorder) count(sub string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

func testManager(t *testing.T, rec *recorder, rules []netcfg.RuleState, links map[string]netcfg.LinkState) *Manager {
	t.Helper()
	dir := t.TempDir()
	return New(Options{
		NetworkDir:   dir,
		RtTablesFile: filepath.Join(dir, "rt_tables.conf"),
		Exec:         rec.exec,
		Slots:        []domain.Slot{domain.Slot(1), domain.Slot(2)},
		ReadRules:    func(context.Context) ([]netcfg.RuleState, error) { return rules, nil },
		ReadLinks:    func(context.Context) (map[string]netcfg.LinkState, error) { return links, nil },
	})
}

func publicRule(addr string) netcfg.RuleState {
	a := netip.MustParseAddr(addr)
	return netcfg.RuleState{
		Priority: domain.RulePrioPublic,
		Table:    rtTableMain,
		Src:      netip.PrefixFrom(a, a.BitLen()),
		IifName:  "lo",
		Action:   "lookup",
	}
}

func TestApplySlotRefusesBeforeEnsureGlobal(t *testing.T) {
	rec := &recorder{}
	m := testManager(t, rec, nil, nil)
	err := m.ApplySlot(context.Background(), domain.Slot(1), "pci-0000:00:14.0-usb-0:13.1:1.0", "")
	if !errors.Is(err, netcfg.ErrGlobalNotReady) {
		t.Fatalf("a slot rule added before the priority %d rule breaks every open customer connection; want ErrGlobalNotReady, got %v", domain.RulePrioPublic, err)
	}
	if rec.contains("networkctl") || rec.contains("udevadm") {
		t.Fatalf("nothing should have been applied, calls: %v", rec.calls)
	}
}

func TestEnsureGlobalAddsThePriority900Rule(t *testing.T) {
	rec := &recorder{}
	m := testManager(t, rec, nil, nil)
	if err := m.EnsureGlobal(context.Background(), []netip.Addr{netip.MustParseAddr("139.99.68.39")}); err != nil {
		t.Fatalf("EnsureGlobal: %v", err)
	}
	want := "ip rule add from 139.99.68.39/32 iif lo lookup main priority 900"
	if !rec.contains(want) {
		t.Fatalf("want %q, calls: %v", want, rec.calls)
	}
}

func TestEnsureGlobalIsIdempotent(t *testing.T) {
	rec := &recorder{}
	m := testManager(t, rec, []netcfg.RuleState{publicRule("139.99.68.39")}, nil)
	if err := m.EnsureGlobal(context.Background(), []netip.Addr{netip.MustParseAddr("139.99.68.39")}); err != nil {
		t.Fatalf("EnsureGlobal: %v", err)
	}
	if rec.contains("rule add") {
		t.Fatalf("an existing rule must not be added again, calls: %v", rec.calls)
	}
}

func TestEnsureGlobalRetiresAStaleLease(t *testing.T) {
	rec := &recorder{}
	m := testManager(t, rec, []netcfg.RuleState{publicRule("139.99.68.39")}, nil)
	if err := m.EnsureGlobal(context.Background(), []netip.Addr{netip.MustParseAddr("139.99.68.40")}); err != nil {
		t.Fatalf("EnsureGlobal: %v", err)
	}
	if !rec.contains("ip rule del priority 900") {
		t.Fatalf("the old lease rule must be removed, calls: %v", rec.calls)
	}
	if !rec.contains("ip rule add from 139.99.68.40/32 iif lo lookup main priority 900") {
		t.Fatalf("the new lease rule must be added, calls: %v", rec.calls)
	}
}

func TestEnsureGlobalRebuildsAMalformedRuleAtOurPriority(t *testing.T) {
	rec := &recorder{}
	stale := netcfg.RuleState{
		Priority: domain.RulePrioPublic,
		Table:    1005,
		Src:      netip.MustParsePrefix("139.99.68.39/32"),
	}
	m := testManager(t, rec, []netcfg.RuleState{stale, publicRule("139.99.68.39")}, nil)
	if err := m.EnsureGlobal(context.Background(), []netip.Addr{netip.MustParseAddr("139.99.68.39")}); err != nil {
		t.Fatalf("EnsureGlobal: %v", err)
	}
	if got := rec.count("ip rule del priority 900"); got != 2 {
		t.Fatalf("every rule at our priority must be cleared, got %d deletes: %v", got, rec.calls)
	}
	if !rec.contains("ip rule add from 139.99.68.39/32 iif lo lookup main priority 900") {
		t.Fatalf("the good rule must be rebuilt, calls: %v", rec.calls)
	}
}

func TestEnsureGlobalRejectsBadHosts(t *testing.T) {
	rec := &recorder{}
	m := testManager(t, rec, nil, nil)
	if err := m.EnsureGlobal(context.Background(), nil); !errors.Is(err, netcfg.ErrNoPublicHost) {
		t.Fatalf("want ErrNoPublicHost, got %v", err)
	}
	err := m.EnsureGlobal(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if !errors.Is(err, netcfg.ErrBadPublicHost) {
		t.Fatalf("want ErrBadPublicHost, got %v", err)
	}
}

func TestApplySlotWritesFilesAndReAssertsTheGlobalRule(t *testing.T) {
	rec := &recorder{}
	m := testManager(t, rec, nil, nil)
	ctx := context.Background()
	if err := m.EnsureGlobal(ctx, []netip.Addr{netip.MustParseAddr("139.99.68.39")}); err != nil {
		t.Fatalf("EnsureGlobal: %v", err)
	}
	if err := m.ApplySlot(ctx, domain.Slot(1), "pci-0000:00:14.0-usb-0:13.1:1.0", ""); err != nil {
		t.Fatalf("ApplySlot: %v", err)
	}
	if !rec.contains("udevadm control --reload") {
		t.Fatalf("a new link file must reload udev, calls: %v", rec.calls)
	}
	if !rec.contains("networkctl reconfigure dg01") {
		t.Fatalf("a new network file must reconfigure the interface, calls: %v", rec.calls)
	}
	if rec.count("ip rule add from 139.99.68.39/32 iif lo lookup main priority 900") != 2 {
		t.Fatalf("networkctl reconfigure drops foreign rules, so the public rule must be re-asserted, calls: %v", rec.calls)
	}
}

func TestApplySlotSecondCallIsQuiet(t *testing.T) {
	rec := &recorder{}
	m := testManager(t, rec, []netcfg.RuleState{publicRule("139.99.68.39")}, nil)
	ctx := context.Background()
	if err := m.EnsureGlobal(ctx, []netip.Addr{netip.MustParseAddr("139.99.68.39")}); err != nil {
		t.Fatalf("EnsureGlobal: %v", err)
	}
	if err := m.ApplySlot(ctx, domain.Slot(1), "pci-x", ""); err != nil {
		t.Fatalf("first ApplySlot: %v", err)
	}
	before := len(rec.calls)
	if err := m.ApplySlot(ctx, domain.Slot(1), "pci-x", ""); err != nil {
		t.Fatalf("second ApplySlot: %v", err)
	}
	if len(rec.calls) != before {
		t.Fatalf("an unchanged slot must not touch udev or networkd, extra calls: %v", rec.calls[before:])
	}
}

func TestApplySlotRejectsAnIDPathTheInterfaceContradicts(t *testing.T) {
	rec := &recorder{}
	links := map[string]netcfg.LinkState{
		"dg01": {Name: "dg01", IDPath: "pci-0000:00:14.0-usb-0:2.4:1.0"},
	}
	m := testManager(t, rec, nil, links)
	ctx := context.Background()
	if err := m.EnsureGlobal(ctx, []netip.Addr{netip.MustParseAddr("139.99.68.39")}); err != nil {
		t.Fatalf("EnsureGlobal: %v", err)
	}
	err := m.ApplySlot(ctx, domain.Slot(1), "pci-0000:00:14.0-usb-0:13.1:1.0", "")
	if !errors.Is(err, netcfg.ErrIDPathNotObserved) {
		t.Fatalf("want ErrIDPathNotObserved, got %v", err)
	}
}

func TestApplySlotRejectsAForeignMAC(t *testing.T) {
	rec := &recorder{}
	links := map[string]netcfg.LinkState{
		"dg01": {Name: "dg01", MAC: "0c:5b:8f:27:9a:01"},
	}
	m := testManager(t, rec, nil, links)
	ctx := context.Background()
	if err := m.EnsureGlobal(ctx, []netip.Addr{netip.MustParseAddr("139.99.68.39")}); err != nil {
		t.Fatalf("EnsureGlobal: %v", err)
	}
	if err := m.ApplySlot(ctx, domain.Slot(1), "pci-x", "0C:5B:8F:27:9A:01"); err != nil {
		t.Fatalf("a matching mac in a different case must be accepted, got %v", err)
	}
	err := m.ApplySlot(ctx, domain.Slot(1), "pci-x", "0c:5b:8f:27:9a:02")
	if !errors.Is(err, netcfg.ErrMACMismatch) {
		t.Fatalf("want ErrMACMismatch, got %v", err)
	}
}

func TestApplySlotRequiresAnIDPath(t *testing.T) {
	rec := &recorder{}
	m := testManager(t, rec, nil, nil)
	ctx := context.Background()
	if err := m.EnsureGlobal(ctx, []netip.Addr{netip.MustParseAddr("139.99.68.39")}); err != nil {
		t.Fatalf("EnsureGlobal: %v", err)
	}
	if err := m.ApplySlot(ctx, domain.Slot(1), "", ""); !errors.Is(err, netcfg.ErrNoIDPath) {
		t.Fatalf("want ErrNoIDPath, got %v", err)
	}
}

func TestOperationsOnAMissingInterfaceAreNoOps(t *testing.T) {
	rec := &recorder{fail: func(cmd string) error {
		return &netcfg.CommandError{
			Name:   "ip",
			Output: `Cannot find device "dg01"`,
			Err:    errors.New("exit status 1"),
		}
	}}
	m := testManager(t, rec, nil, nil)
	ctx := context.Background()
	if err := m.RemoveSlot(ctx, domain.Slot(1)); err != nil {
		t.Fatalf("RemoveSlot on a missing interface must be a no-op, got %v", err)
	}
	if !rec.contains("ip rule del from 192.168.101.100/32 lookup 1001 priority 1001") ||
		!rec.contains("ip rule del uidrange 6101-6101 lookup 1001 priority 1501") {
		t.Fatalf("both slot rules must be cleaned up, calls: %v", rec.calls)
	}
	if !rec.contains("ip route flush table 1001") {
		t.Fatalf("the slot route table must be flushed, calls: %v", rec.calls)
	}
}

func TestInvalidSlotIsRejectedEverywhere(t *testing.T) {
	rec := &recorder{}
	m := testManager(t, rec, nil, nil)
	ctx := context.Background()
	if err := m.RemoveSlot(ctx, domain.Slot(0)); !errors.Is(err, netcfg.ErrInvalidSlot) {
		t.Fatalf("want ErrInvalidSlot, got %v", err)
	}
	if err := m.ApplySlot(ctx, domain.Slot(domain.MaxSlots+1), "p", ""); !errors.Is(err, netcfg.ErrInvalidSlot) {
		t.Fatalf("want ErrInvalidSlot, got %v", err)
	}
}

func TestEnsureRouteTableNamesIsIdempotent(t *testing.T) {
	rec := &recorder{}
	m := testManager(t, rec, nil, nil)
	ctx := context.Background()
	if err := m.EnsureRouteTableNames(ctx); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := m.EnsureRouteTableNames(ctx); err != nil {
		t.Fatalf("second: %v", err)
	}
}

func TestConcurrentAppliesDoNotInterleaveTheirReadModifyWrite(t *testing.T) {
	rec := &recorder{}
	rules := []netcfg.RuleState{publicRule("203.0.113.7"), publicRule("203.0.113.8")}
	links := map[string]netcfg.LinkState{
		"dg01": {Name: "dg01", IDPath: "id-1", OperState: "up"},
		"dg02": {Name: "dg02", IDPath: "id-2", OperState: "up"},
	}

	var live, maxLive atomic.Int32
	readRules := func(context.Context) ([]netcfg.RuleState, error) {
		n := live.Add(1)
		for {
			m := maxLive.Load()
			if n <= m || maxLive.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		live.Add(-1)
		return rules, nil
	}

	dir := t.TempDir()
	m := New(Options{
		NetworkDir:   dir,
		RtTablesFile: filepath.Join(dir, "rt_tables.conf"),
		Exec:         rec.exec,
		Slots:        []domain.Slot{domain.Slot(1), domain.Slot(2)},
		ReadRules:    readRules,
		ReadLinks:    func(context.Context) (map[string]netcfg.LinkState, error) { return links, nil },
	})

	hosts := []netip.Addr{netip.MustParseAddr("203.0.113.7")}
	if err := m.EnsureGlobal(context.Background(), hosts); err != nil {
		t.Fatalf("EnsureGlobal: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- m.EnsureGlobal(context.Background(), hosts)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- m.RemoveSlot(context.Background(), domain.Slot(2))
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent apply: %v", err)
		}
	}

	if got := maxLive.Load(); got != 1 {
		t.Fatalf("%d applies read the rule table at once, want the writes serialized", got)
	}
}

func TestRemoveSlotLeavesAForeignRuleSharingThePriority(t *testing.T) {
	rec := &recorder{}
	foreign := netcfg.RuleState{
		Priority: domain.Slot(1).RulePrioSrc(),
		Table:    99,
		Src:      netip.MustParsePrefix("10.7.0.0/16"),
	}
	m := testManager(t, rec, []netcfg.RuleState{foreign}, nil)

	if err := m.RemoveSlot(context.Background(), domain.Slot(1)); err != nil {
		t.Fatalf("RemoveSlot: %v", err)
	}
	if n := rec.count("ip rule del from 192.168.101.100/32 lookup 1001 priority 1001"); n != 1 {
		t.Fatalf("the slot rule was deleted %d times, want exactly one precise delete", n)
	}
	if rec.contains("ip rule del priority 1001") {
		t.Fatalf("a delete by bare priority would take the foreign rule with it, calls: %v", rec.calls)
	}
}
