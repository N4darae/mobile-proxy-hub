package linux

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"sync"

	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/netcfg"
	"github.com/n4darae/huawei-API/src/internal/netcfg/files"
)

type RuleReader func(ctx context.Context) ([]netcfg.RuleState, error)

type LinkReader func(ctx context.Context) (map[string]netcfg.LinkState, error)

type Options struct {
	NetworkDir    string
	RtTablesFile  string
	ProcRoot      string
	Exec          netcfg.Exec
	ProbeDst      netip.Addr
	RequireIDPath bool
	Slots         []domain.Slot
	ReadRules     RuleReader
	ReadLinks     LinkReader
}

type Manager struct {
	networkDir    string
	rtTablesFile  string
	exec          netcfg.Exec
	renderer      *files.Renderer
	reloader      files.Reloader
	observer      *Observer
	probeDst      netip.Addr
	requireIDPath bool
	slots         []domain.Slot
	readRules     RuleReader
	readLinks     LinkReader

	apply sync.Mutex

	mu          sync.Mutex
	publicHosts []netip.Addr
	globalReady bool
	applied     map[domain.Slot]struct{}
}

var _ netcfg.Manager = (*Manager)(nil)

func New(o Options) *Manager {
	if o.NetworkDir == "" {
		o.NetworkDir = files.DefaultNetworkDir()
	}
	if o.RtTablesFile == "" {
		o.RtTablesFile = files.DefaultRouteTablesFile()
	}
	if o.Exec == nil {
		o.Exec = netcfg.SystemExec
	}
	if !o.ProbeDst.IsValid() {
		o.ProbeDst = netip.AddrFrom4([4]byte{1, 1, 1, 1})
	}
	if len(o.Slots) == 0 {
		o.Slots = domain.Slots()
	}
	obs := NewObserver(o.Exec)
	if o.ProcRoot != "" {
		obs.ProcRoot = o.ProcRoot
	}
	if o.ReadRules == nil {
		o.ReadRules = obs.Rules
	}
	if o.ReadLinks == nil {
		o.ReadLinks = obs.Links
	}
	return &Manager{
		networkDir:    o.NetworkDir,
		rtTablesFile:  o.RtTablesFile,
		exec:          o.Exec,
		renderer:      files.NewRenderer(o.NetworkDir),
		reloader:      files.NewReloader(o.Exec),
		observer:      obs,
		probeDst:      o.ProbeDst,
		requireIDPath: o.RequireIDPath,
		slots:         o.Slots,
		readRules:     o.ReadRules,
		readLinks:     o.ReadLinks,
		applied:       map[domain.Slot]struct{}{},
	}
}

func (m *Manager) EnsureGlobal(ctx context.Context, publicHosts []netip.Addr) error {
	m.apply.Lock()
	defer m.apply.Unlock()
	return m.ensureGlobal(ctx, publicHosts)
}

func (m *Manager) ensureGlobal(ctx context.Context, publicHosts []netip.Addr) error {
	if len(publicHosts) == 0 {
		return netcfg.ErrNoPublicHost
	}
	want := make([]netip.Addr, 0, len(publicHosts))
	for _, h := range publicHosts {
		if !netcfg.ValidPublicHost(h) {
			return fmt.Errorf("%w: %s", netcfg.ErrBadPublicHost, h)
		}
		want = append(want, h)
	}
	rules, err := m.readRules(ctx)
	if err != nil {
		return err
	}
	wanted := map[netip.Addr]bool{}
	for _, h := range want {
		wanted[h] = true
	}

	have := map[netip.Addr]bool{}
	total, stale := 0, 0
	for _, r := range rules {
		if r.Priority != domain.RulePrioPublic {
			continue
		}
		total++
		addr := r.Src.Addr()
		if isPublicRule(r) && wanted[addr] && !have[addr] {
			have[addr] = true
			continue
		}
		stale++
	}

	if stale > 0 {
		for i := 0; i < total; i++ {
			if err := m.ruleDel(ctx, []string{"priority", strconv.Itoa(domain.RulePrioPublic)}); err != nil {
				return err
			}
		}
		have = map[netip.Addr]bool{}
	}
	for _, h := range want {
		if have[h] {
			continue
		}
		if err := m.ruleAdd(ctx, publicRuleArgs(h)); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.publicHosts = want
	m.globalReady = true
	m.mu.Unlock()
	return nil
}

func countRulesAt(rules []netcfg.RuleState, prio int) int {
	n := 0
	for _, r := range rules {
		if r.Priority == prio {
			n++
		}
	}
	return n
}

func isPublicRule(r netcfg.RuleState) bool {
	if !r.Src.IsValid() || r.Src.Bits() != r.Src.Addr().BitLen() {
		return false
	}
	return r.IifName == "lo" && r.Table == rtTableMain
}

func publicRuleArgs(a netip.Addr) []string {
	return []string{
		"from", netip.PrefixFrom(a, a.BitLen()).String(),
		"iif", "lo",
		"lookup", "main",
		"priority", strconv.Itoa(domain.RulePrioPublic),
	}
}

func (m *Manager) ruleAdd(ctx context.Context, args []string) error {
	_, err := m.exec(ctx, "ip", append([]string{"rule", "add"}, args...)...)
	return err
}

func (m *Manager) ruleDel(ctx context.Context, args []string) error {
	_, err := m.exec(ctx, "ip", append([]string{"rule", "del"}, args...)...)
	return netcfg.IgnoreAbsent(err)
}

func (m *Manager) EnsureRouteTableNames(ctx context.Context) error {
	_, err := files.WriteRouteTables(m.rtTablesFile, m.slots)
	return err
}

func (m *Manager) ApplySlot(ctx context.Context, s domain.Slot, idPath, mac string) error {
	if !s.Valid() {
		return netcfg.ErrInvalidSlot
	}
	m.apply.Lock()
	defer m.apply.Unlock()
	m.mu.Lock()
	ready := m.globalReady
	m.mu.Unlock()
	if !ready {
		return netcfg.ErrGlobalNotReady
	}
	links, err := m.readLinks(ctx)
	if err != nil {
		return err
	}
	if err := m.checkIDPath(s, idPath, links); err != nil {
		return err
	}
	if err := checkMAC(s, mac, links); err != nil {
		return err
	}
	changed, err := m.renderer.WriteSlot(s, idPath)
	if err != nil {
		return err
	}
	if err := m.reloader.Apply(ctx, s.IfaceName(), changed); err != nil {
		return err
	}
	m.mu.Lock()
	m.applied[s] = struct{}{}
	hosts := append([]netip.Addr(nil), m.publicHosts...)
	m.mu.Unlock()
	if changed.Network && len(hosts) > 0 {
		return m.ensureGlobal(ctx, hosts)
	}
	return nil
}

func (m *Manager) checkIDPath(s domain.Slot, idPath string, links map[string]netcfg.LinkState) error {
	if idPath == "" {
		return netcfg.ErrNoIDPath
	}
	if l, ok := links[s.IfaceName()]; ok && l.IDPath != "" && l.IDPath != idPath {
		return fmt.Errorf("%w: %s reports %q, enrolled %q", netcfg.ErrIDPathNotObserved, s.IfaceName(), l.IDPath, idPath)
	}
	if !m.requireIDPath {
		return nil
	}
	for _, l := range links {
		if l.IDPath == idPath {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", netcfg.ErrIDPathNotObserved, idPath)
}

func checkMAC(s domain.Slot, mac string, links map[string]netcfg.LinkState) error {
	if mac == "" {
		return nil
	}
	l, ok := links[s.IfaceName()]
	if !ok || l.MAC == "" {
		return nil
	}
	if !equalMAC(l.MAC, mac) {
		return fmt.Errorf("%w: %s has %s, enrolled %s", netcfg.ErrMACMismatch, s.IfaceName(), l.MAC, mac)
	}
	return nil
}

func equalMAC(a, b string) bool {
	return normalizeMAC(a) == normalizeMAC(b)
}

func normalizeMAC(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'F':
			out = append(out, c+('a'-'A'))
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'):
			out = append(out, c)
		}
	}
	return string(out)
}

func (m *Manager) RemoveSlot(ctx context.Context, s domain.Slot) error {
	if !s.Valid() {
		return netcfg.ErrInvalidSlot
	}
	m.apply.Lock()
	defer m.apply.Unlock()
	changed, err := m.renderer.RemoveSlot(s)
	if err != nil {
		return err
	}
	if changed.Any() {
		if err := m.reloader.ApplyNetwork(ctx, s.IfaceName()); err != nil {
			return err
		}
	}
	rules, err := m.readRules(ctx)
	if err != nil {
		return err
	}
	for _, prio := range []int{s.RulePrioSrc(), s.RulePrioUID()} {
		n := countRulesAt(rules, prio)
		if n < 1 {
			n = 1
		}
		for i := 0; i < n; i++ {
			if err := m.ruleDel(ctx, []string{"priority", strconv.Itoa(prio)}); err != nil {
				return err
			}
		}
	}
	if _, err := m.exec(ctx, "ip", "route", "flush", "table", strconv.Itoa(s.RouteTable())); err != nil {
		if err := netcfg.IgnoreAbsent(err); err != nil {
			return err
		}
	}
	m.mu.Lock()
	delete(m.applied, s)
	m.mu.Unlock()
	return nil
}

func (m *Manager) Observe(ctx context.Context) (netcfg.Observation, error) {
	var obs netcfg.Observation
	links, err := m.readLinks(ctx)
	if err != nil {
		return obs, err
	}
	rules, err := m.readRules(ctx)
	if err != nil {
		return obs, err
	}
	routes, err := m.observer.Routes(ctx)
	if err != nil {
		return obs, err
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	obs.Links = links
	obs.Rules = rules
	obs.Routes = routes
	obs.DuplicateAddrs = DuplicateAddrs(links)
	obs.RpFilterAll = m.observer.RpFilterAll()
	obs.IPForward = m.observer.IPForward()
	obs.RouteTableNamesOK = files.RouteTablesComplete(m.rtTablesFile, m.slots)
	for _, r := range rules {
		if r.Priority == domain.RulePrioPublic {
			if isPublicRule(r) {
				obs.PublicSrcRules = append(obs.PublicSrcRules, r)
			} else {
				obs.ForeignRuleBelowCeil = append(obs.ForeignRuleBelowCeil, r)
			}
			continue
		}
		if r.Priority <= 0 || r.Priority >= domain.ForeignRuleCeil {
			continue
		}
		if netcfg.IsOurRulePriority(r.Priority) {
			continue
		}
		obs.ForeignRuleBelowCeil = append(obs.ForeignRuleBelowCeil, r)
	}
	return obs, nil
}

func (m *Manager) Subscribe(ctx context.Context) (<-chan netcfg.LinkEvent, func(), error) {
	return m.observer.Subscribe(ctx)
}

func (m *Manager) PublicHosts() []netip.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]netip.Addr(nil), m.publicHosts...)
}

func (m *Manager) NetworkDir() string { return m.networkDir }

func (m *Manager) RouteTablesFile() string { return m.rtTablesFile }

func (m *Manager) Renderer() *files.Renderer { return m.renderer }
