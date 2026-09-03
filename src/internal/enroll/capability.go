package enroll

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/n4darae/huawei-API/src/internal/config"
	"github.com/n4darae/huawei-API/src/internal/device"
	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/fw"
	"github.com/n4darae/huawei-API/src/internal/netcfg"
	"github.com/n4darae/huawei-API/src/internal/netcfg/linux"
)

type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail"`
	Fatal   bool   `json:"fatal"`
	Skipped bool   `json:"skipped,omitempty"`
}

type Report []Check

func (r Report) Failed() Report {
	var out Report
	for _, c := range r {
		if !c.OK {
			out = append(out, c)
		}
	}
	return out
}

func (r Report) FatalFailed() Report {
	var out Report
	for _, c := range r {
		if !c.OK && c.Fatal {
			out = append(out, c)
		}
	}
	return out
}

func (r Report) Green(fatalOnly bool) bool {
	if fatalOnly {
		return len(r.FatalFailed()) == 0
	}
	return len(r.Failed()) == 0
}

func (r Report) Text() string {
	width := 0
	for _, c := range r {
		if len(c.Name) > width {
			width = len(c.Name)
		}
	}
	var b strings.Builder
	for _, c := range r {
		mark := "FAIL"
		switch {
		case c.Skipped:
			mark = "skip"
		case c.OK:
			mark = " ok "
		}
		tag := ""
		if !c.OK && c.Fatal {
			tag = " [fatal]"
		}
		fmt.Fprintf(&b, "[%s] %-*s  %s%s\n", mark, width, c.Name, c.Detail, tag)
	}
	return b.String()
}

const (
	CheckBinary       = "3proxy_binary"
	CheckConntrack    = "conntrack_netlink"
	CheckModemManager = "modemmanager_ignored"
	CheckRtTables     = "rt_tables_dir"
	CheckRpFilter     = "rp_filter"
	CheckIPForward    = "ip_forward"
	CheckForeignRule  = "no_foreign_rule_below_900"
	CheckPublicRule   = "public_src_rule_present"
	CheckPortsFree    = "ports_free"
	CheckGroup        = "group_dongled"
	CheckNftTable     = "nft_table"
	CheckStaticAddr   = "public_addr_static"
	CheckKernel       = "kernel_version"
	CheckBackup       = "recent_backup"
)

const (
	MinKernelMajor = 6
	MinKernelMinor = 2

	PinFileName = "3proxy.pin"

	UdevRuleName = "99-" + config.Product + "-mm-ignore.rules"
)

var UdevRuleDirs = []string{
	"/etc/udev/rules.d",
	"/usr/lib/udev/rules.d",
	"/lib/udev/rules.d",
}

type PreflightOptions struct {
	Bin3proxy   string
	BinDir      string
	BackupDir   string
	GroupFile   string
	ProcRoot    string
	SysRoot     string
	RtTablesDir string

	SkipNetcfg   bool
	SkipFirewall bool
	SkipProxy    bool
	SkipDevice   bool

	UdevRuleDirs []string
	PublicHosts  []netip.Addr
	PanelAddr    string
	MetricsAddr  string
	Slots        []domain.Slot

	Exec          netcfg.Exec
	ReadRules     func(ctx context.Context) ([]netcfg.RuleState, error)
	HasListener   func(netip.Addr, int) (bool, error)
	Conntrack     func() (int, error)
	VerifyNft     func(ctx context.Context) error
	KernelRelease func() (string, error)
	UnitEnabled   func(ctx context.Context, unit string) (string, error)

	Now          time.Time
	BackupMaxAge time.Duration
}

func (o *PreflightOptions) defaults() {
	if o.Bin3proxy == "" {
		o.Bin3proxy = config.Bin3proxy
	}
	if o.BinDir == "" {
		o.BinDir = config.BinDir
	}
	if o.BackupDir == "" {
		o.BackupDir = config.BackupDir
	}
	if o.GroupFile == "" {
		o.GroupFile = "/etc/group"
	}
	if o.ProcRoot == "" {
		o.ProcRoot = "/proc"
	}
	if o.SysRoot == "" {
		o.SysRoot = DefaultSysfsRoot
	}
	if o.RtTablesDir == "" {
		o.RtTablesDir = config.RtTablesDir
	}
	if len(o.UdevRuleDirs) == 0 {
		o.UdevRuleDirs = UdevRuleDirs
	}
	if o.PanelAddr == "" {
		o.PanelAddr = config.PanelAddr
	}
	if o.MetricsAddr == "" {
		o.MetricsAddr = config.MetricsAddr
	}
	if len(o.Slots) == 0 {
		o.Slots = domain.Slots()
	}
	if o.Exec == nil {
		o.Exec = netcfg.SystemExec
	}
	if o.ReadRules == nil {
		obs := linux.NewObserver(o.Exec)
		obs.ProcRoot = o.ProcRoot
		obs.SysRoot = o.SysRoot
		o.ReadRules = obs.Rules
	}
	if o.HasListener == nil {
		o.HasListener = fw.HasListener
	}
	if o.Conntrack == nil {
		o.Conntrack = CountConntrack
	}
	if o.VerifyNft == nil {
		o.VerifyNft = fw.NewNft(fw.Options{}).Verify
	}
	if o.KernelRelease == nil {
		o.KernelRelease = KernelRelease
	}
	if o.UnitEnabled == nil {
		o.UnitEnabled = func(ctx context.Context, unit string) (string, error) {
			out, err := o.Exec(ctx, "systemctl", "is-enabled", unit)
			return strings.TrimSpace(string(out)), err
		}
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.BackupMaxAge == 0 {
		o.BackupMaxAge = secretsBackupMaxAge
	}
}

const secretsBackupMaxAge = 7 * 24 * time.Hour

func Preflight(ctx context.Context, o PreflightOptions) Report {
	o.defaults()
	r := Report{
		skipUnless(!o.SkipProxy, CheckBinary, "the proxy backend is simulated", func() Check { return checkBinary(o) }),
		skipUnless(!o.SkipFirewall, CheckConntrack, "the firewall backend is simulated", func() Check { return checkConntrack(o) }),
		skipUnless(!o.SkipDevice, CheckModemManager, "the device backend is simulated", func() Check { return checkModemManager(ctx, o) }),
		skipUnless(!o.SkipNetcfg, CheckRtTables, "the netcfg backend is simulated", func() Check { return checkRtTables(o) }),
		skipUnless(!o.SkipNetcfg, CheckRpFilter, "the netcfg backend is simulated", func() Check { return checkRpFilter(o) }),
		skipUnless(!o.SkipNetcfg, CheckIPForward, "the netcfg backend is simulated", func() Check { return checkIPForward(o) }),
		skipUnless(!o.SkipNetcfg, CheckForeignRule, "the netcfg backend is simulated", func() Check { return checkRules(ctx, o) }),
		skipUnless(!o.SkipNetcfg, CheckPublicRule, "the netcfg backend is simulated", func() Check { return checkPublicRule(ctx, o) }),
		checkPorts(o),
		skipUnless(!o.SkipProxy, CheckGroup, "the proxy backend is simulated", func() Check { return checkGroup(o) }),
		skipUnless(!o.SkipFirewall, CheckNftTable, "the firewall backend is simulated", func() Check { return checkNft(ctx, o) }),
		skipUnless(!o.SkipNetcfg, CheckStaticAddr, "the netcfg backend is simulated", func() Check { return checkStaticAddr(ctx, o) }),
		skipUnless(!o.SkipNetcfg && !o.SkipFirewall, CheckKernel, "netcfg and the firewall are both simulated", func() Check { return checkKernel(o) }),
		checkBackup(o),
	}
	for i := range r {
		r[i].Detail = strings.Join(strings.Fields(r[i].Detail), " ")
	}
	return r
}

func skipUnless(run bool, name, why string, check func() Check) Check {
	if run {
		return check()
	}
	return Check{Name: name, OK: true, Skipped: true, Detail: "not checked, " + why}
}

func PinPath(binDir string) string { return filepath.Join(binDir, PinFileName) }

type Pin struct {
	SHA256 string
	Commit string
}

func (p Pin) String() string { return "sha256:" + p.SHA256 + " commit:" + p.Commit }

func ParsePin(raw string) (Pin, error) {
	var p Pin
	for _, f := range strings.Fields(raw) {
		k, v, ok := strings.Cut(f, ":")
		if !ok {
			continue
		}
		switch k {
		case "sha256":
			p.SHA256 = strings.ToLower(v)
		case "commit":
			p.Commit = strings.ToLower(v)
		}
	}
	if p.SHA256 == "" || p.Commit == "" {
		return Pin{}, fmt.Errorf("%w: pin record %q", domain.ErrInvalid, strings.TrimSpace(raw))
	}
	return p, nil
}

func ReadPin(binDir string) (Pin, error) {
	raw, err := os.ReadFile(PinPath(binDir))
	if err != nil {
		return Pin{}, err
	}
	return ParsePin(string(raw))
}

func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func checkBinary(o PreflightOptions) Check {
	c := Check{Name: CheckBinary, Fatal: true}
	st, err := os.Stat(o.Bin3proxy)
	if err != nil {
		c.Detail = fmt.Sprintf("%s is missing: build the pinned commit %s and run bootstrap", o.Bin3proxy, config.Pin3proxyCommit)
		return c
	}
	if st.Mode()&0o111 == 0 {
		c.Detail = o.Bin3proxy + " is not executable"
		return c
	}
	sum, err := FileSHA256(o.Bin3proxy)
	if err != nil {
		c.Detail = fmt.Sprintf("cannot hash %s: %v", o.Bin3proxy, err)
		return c
	}
	pin, err := ReadPin(o.BinDir)
	if err != nil {
		c.Detail = fmt.Sprintf("%s holds no pin record (binary sha256 %s): run bootstrap to record it", PinPath(o.BinDir), sum)
		return c
	}
	if pin.Commit != strings.ToLower(config.Pin3proxyCommit) {
		c.Detail = fmt.Sprintf("pin record names commit %s, this build requires %s", pin.Commit, config.Pin3proxyCommit)
		return c
	}
	if pin.SHA256 != sum {
		c.Detail = fmt.Sprintf("%s hashes to %s, pin record says %s", o.Bin3proxy, sum, pin.SHA256)
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("%s sha256 %s from commit %s", o.Bin3proxy, sum[:16], pin.Commit[:12])
	return c
}

func checkConntrack(o PreflightOptions) Check {
	c := Check{Name: CheckConntrack, Fatal: true}
	n, err := o.Conntrack()
	if err != nil {
		c.Detail = fmt.Sprintf("conntrack dump over NETLINK_NETFILTER failed: %v", err)
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("NETLINK_NETFILTER dump returned %d entries", n)
	return c
}

func checkModemManager(ctx context.Context, o PreflightOptions) Check {
	c := Check{Name: CheckModemManager, Fatal: true}
	for _, dir := range o.UdevRuleDirs {
		p := filepath.Join(dir, UdevRuleName)
		if _, err := os.Stat(p); err == nil {
			c.OK = true
			c.Detail = "udev ignore rule installed at " + p
			return c
		}
	}
	state, err := o.UnitEnabled(ctx, "ModemManager.service")
	switch {
	case err != nil && state == "":
		c.Detail = fmt.Sprintf("cannot read the ModemManager.service state (%v); install %s so it cannot claim a dongle netdev", err, UdevRuleName)
	case state == "disabled" || state == "masked" || state == "not-found":
		c.OK = true
		c.Detail = "ModemManager.service is " + state
	default:
		c.Detail = fmt.Sprintf("ModemManager.service is %q and %s is not installed; it will claim every dongle netdev", state, UdevRuleName)
	}
	return c
}

func checkRtTables(o PreflightOptions) Check {
	c := Check{Name: CheckRtTables, Fatal: true}
	st, err := os.Stat(o.RtTablesDir)
	if err != nil || !st.IsDir() {
		c.Detail = o.RtTablesDir + " does not exist; iproute2 cannot resolve the per-slot table names"
		return c
	}
	c.OK = true
	c.Detail = o.RtTablesDir + " exists"
	return c
}

func readIntFile(root, rel string) (int, error) {
	raw, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(raw)))
}

func checkRpFilter(o PreflightOptions) Check {
	c := Check{Name: CheckRpFilter, Fatal: true}
	v, err := readIntFile(o.ProcRoot, "sys/net/ipv4/conf/all/rp_filter")
	if err != nil {
		c.Detail = fmt.Sprintf("cannot read net.ipv4.conf.all.rp_filter: %v", err)
		return c
	}
	if v != netcfg.RequiredRpFilterAll {
		c.Detail = fmt.Sprintf("net.ipv4.conf.all.rp_filter is %d, must be %d (loose) or asymmetric dongle return paths are dropped", v, netcfg.RequiredRpFilterAll)
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("net.ipv4.conf.all.rp_filter = %d", v)
	return c
}

func checkIPForward(o PreflightOptions) Check {
	c := Check{Name: CheckIPForward, Fatal: true}
	v, err := readIntFile(o.ProcRoot, "sys/net/ipv4/ip_forward")
	if err != nil {
		c.Detail = fmt.Sprintf("cannot read net.ipv4.ip_forward: %v", err)
		return c
	}
	if (v != 0) != netcfg.RequiredIPForward {
		c.Detail = fmt.Sprintf("net.ipv4.ip_forward is %d, must be 0; this host proxies, it does not route", v)
		return c
	}
	c.OK = true
	c.Detail = "net.ipv4.ip_forward = 0"
	return c
}

func checkRules(ctx context.Context, o PreflightOptions) Check {
	c := Check{Name: CheckForeignRule, Fatal: true}
	rules, err := o.ReadRules(ctx)
	if err != nil {
		c.Detail = fmt.Sprintf("cannot dump ip rules: %v", err)
		return c
	}
	var foreign []string
	for _, r := range rules {
		if r.Priority <= 0 || r.Priority >= domain.RulePrioPublic {
			continue
		}
		if netcfg.IsOurRulePriority(r.Priority) {
			continue
		}
		foreign = append(foreign, fmt.Sprintf("%d: %s", r.Priority, strings.TrimSpace(r.Raw)))
	}
	if len(foreign) > 0 {
		sort.Strings(foreign)
		c.Detail = "foreign rules evaluate before priority 900: " + strings.Join(foreign, "; ")
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("no foreign rule below priority %d among %d rules", domain.RulePrioPublic, len(rules))
	return c
}

func checkPublicRule(ctx context.Context, o PreflightOptions) Check {
	c := Check{Name: CheckPublicRule, Fatal: true}
	if len(o.PublicHosts) == 0 {
		c.Detail = "no public host configured; set DONGLED_PUBLIC_HOST"
		return c
	}
	rules, err := o.ReadRules(ctx)
	if err != nil {
		c.Detail = fmt.Sprintf("cannot dump ip rules: %v", err)
		return c
	}
	have := map[netip.Addr]bool{}
	for _, r := range rules {
		if r.Priority != domain.RulePrioPublic || r.IifName != "lo" {
			continue
		}
		if !r.Src.IsValid() || r.Src.Bits() != r.Src.Addr().BitLen() {
			continue
		}
		have[r.Src.Addr()] = true
	}
	var missing []string
	for _, h := range o.PublicHosts {
		if !have[h] {
			missing = append(missing, h.String())
		}
	}
	if len(missing) > 0 {
		c.Detail = fmt.Sprintf("missing `ip rule add from %s iif lo lookup main priority %d`; without it every customer handshake dies as a timeout",
			strings.Join(missing, ","), domain.RulePrioPublic)
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("priority %d rule present for %d public address(es)", domain.RulePrioPublic, len(o.PublicHosts))
	return c
}

type Port struct {
	Addr netip.Addr
	Port int
	Role string
}

func PreflightPorts(panelAddr, metricsAddr string, public netip.Addr, slots []domain.Slot) []Port {
	loop := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	out := []Port{
		{Addr: addrOfListen(panelAddr, loop), Port: portOfListen(panelAddr, config.PanelPort), Role: "panel"},
		{Addr: addrOfListen(metricsAddr, loop), Port: portOfListen(metricsAddr, config.MetricsPort), Role: "metrics"},
		{Addr: loop, Port: config.ProxyValidatePort, Role: "validate"},
	}
	bind := public
	if !bind.IsValid() {
		bind = loop
	}
	for _, s := range slots {
		out = append(out,
			Port{Addr: bind, Port: s.SocksPort(), Role: "socks " + s.String()},
			Port{Addr: bind, Port: s.HTTPPort(), Role: "http " + s.String()},
		)
	}
	return out
}

func addrOfListen(addr string, fallback netip.Addr) netip.Addr {
	host, _, ok := strings.Cut(addr, ":")
	if !ok {
		return fallback
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return fallback
	}
	return a
}

func portOfListen(addr string, fallback int) int {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return fallback
	}
	p, err := strconv.Atoi(addr[i+1:])
	if err != nil {
		return fallback
	}
	return p
}

func checkPorts(o PreflightOptions) Check {
	c := Check{Name: CheckPortsFree}
	var public netip.Addr
	if len(o.PublicHosts) > 0 {
		public = o.PublicHosts[0]
	}
	ports := PreflightPorts(o.PanelAddr, o.MetricsAddr, public, o.Slots)
	var busy []string
	for _, p := range ports {
		taken, err := o.HasListener(p.Addr, p.Port)
		if err != nil {
			c.Detail = fmt.Sprintf("cannot enumerate listeners: %v", err)
			return c
		}
		if taken {
			busy = append(busy, fmt.Sprintf("%d (%s)", p.Port, p.Role))
		}
	}
	if len(busy) > 0 {
		c.Detail = fmt.Sprintf("%d of %d ports already bound: %s", len(busy), len(ports), strings.Join(busy, ", "))
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("all %d reserved ports are free", len(ports))
	return c
}

func checkGroup(o PreflightOptions) Check {
	c := Check{Name: CheckGroup, Fatal: true}
	gid, err := LookupGroupGID(o.GroupFile, config.GroupName)
	if err != nil {
		c.Detail = fmt.Sprintf("group %s not found in %s: install %s and run systemd-sysusers", config.GroupName, o.GroupFile, config.Product+".conf")
		return c
	}
	if gid != config.GroupGID {
		c.Detail = fmt.Sprintf("group %s has gid %d, the nft egress chain matches gid %d", config.GroupName, gid, config.GroupGID)
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("group %s has gid %d", config.GroupName, gid)
	return c
}

func LookupGroupGID(groupFile, name string) (int, error) {
	f, err := os.Open(groupFile)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 3 || fields[0] != name {
			continue
		}
		return strconv.Atoi(fields[2])
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("%w: group %s", domain.ErrNotFound, name)
}

func checkNft(ctx context.Context, o PreflightOptions) Check {
	c := Check{Name: CheckNftTable, Fatal: true}
	if err := o.VerifyNft(ctx); err != nil {
		c.Detail = fmt.Sprintf("table %s %s did not verify: %v", config.NftFamily, config.NftTable, err)
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("table %s %s present and ordered", config.NftFamily, config.NftTable)
	return c
}

func checkStaticAddr(ctx context.Context, o PreflightOptions) Check {
	c := Check{Name: CheckStaticAddr}
	if len(o.PublicHosts) == 0 {
		c.Detail = "no public host configured; set DONGLED_PUBLIC_HOST"
		return c
	}
	out, err := o.Exec(ctx, "ip", "-4", "-o", "addr", "show")
	if err != nil {
		c.Detail = fmt.Sprintf("cannot list addresses: %v", err)
		return c
	}
	leased := map[netip.Addr]string{}
	seen := map[netip.Addr]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		a, ok := addrOfLine(line)
		if !ok {
			continue
		}
		seen[a] = true
		if strings.Contains(line, " dynamic ") || !strings.Contains(line, "valid_lft forever") {
			leased[a] = strings.TrimSpace(line)
		}
	}
	var bad []string
	for _, h := range o.PublicHosts {
		if !seen[h] {
			bad = append(bad, h.String()+" is not configured on this host")
			continue
		}
		if _, dyn := leased[h]; dyn {
			bad = append(bad, h.String()+" is a DHCP lease")
		}
	}
	if len(bad) > 0 {
		c.Detail = strings.Join(bad, "; ") + "; a lease change silently breaks every `internal` bind"
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("%d public address(es) are static", len(o.PublicHosts))
	return c
}

func addrOfLine(line string) (netip.Addr, bool) {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f != "inet" || i+1 >= len(fields) {
			continue
		}
		p, err := netip.ParsePrefix(fields[i+1])
		if err != nil {
			return netip.Addr{}, false
		}
		return p.Addr(), true
	}
	return netip.Addr{}, false
}

func ParseKernelRelease(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	cut := strings.IndexFunc(s, func(r rune) bool {
		return r != '.' && (r < '0' || r > '9')
	})
	if cut >= 0 {
		s = s[:cut]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("%w: kernel release %q", domain.ErrInvalid, s)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("%w: kernel release %q", domain.ErrInvalid, s)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("%w: kernel release %q", domain.ErrInvalid, s)
	}
	return major, minor, nil
}

func KernelAtLeast(release string, major, minor int) (bool, error) {
	gotMajor, gotMinor, err := ParseKernelRelease(release)
	if err != nil {
		return false, err
	}
	if gotMajor != major {
		return gotMajor > major, nil
	}
	return gotMinor >= minor, nil
}

func checkKernel(o PreflightOptions) Check {
	c := Check{Name: CheckKernel, Fatal: true}
	rel, err := o.KernelRelease()
	if err != nil {
		c.Detail = fmt.Sprintf("cannot read the kernel release: %v", err)
		return c
	}
	ok, err := KernelAtLeast(rel, MinKernelMajor, MinKernelMinor)
	if err != nil {
		c.Detail = fmt.Sprintf("cannot parse kernel release %q: %v", rel, err)
		return c
	}
	if !ok {
		c.Detail = fmt.Sprintf("kernel %s is older than %d.%d; renaming a live interface returns EBUSY there", rel, MinKernelMajor, MinKernelMinor)
		return c
	}
	c.OK = true
	c.Detail = "kernel " + rel
	return c
}

func NewestBackup(dir string) (string, time.Time, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", time.Time{}, err
	}
	var (
		newest string
		at     time.Time
	)
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), config.Product+"-") || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(at) {
			at = info.ModTime()
			newest = filepath.Join(dir, e.Name())
		}
	}
	if newest == "" {
		return "", time.Time{}, fmt.Errorf("%w: no backup in %s", domain.ErrNotFound, dir)
	}
	return newest, at, nil
}

func checkBackup(o PreflightOptions) Check {
	c := Check{Name: CheckBackup}
	path, at, err := NewestBackup(o.BackupDir)
	if err != nil {
		c.Detail = fmt.Sprintf("no usable backup in %s: run `%s backup`", o.BackupDir, config.Product)
		return c
	}
	age := o.Now.Sub(at)
	if age > o.BackupMaxAge {
		c.Detail = fmt.Sprintf("newest backup %s is %s old, limit is %s", path, age.Round(time.Hour), o.BackupMaxAge)
		return c
	}
	c.OK = true
	c.Detail = fmt.Sprintf("%s is %s old", path, age.Round(time.Minute))
	return c
}

type DeviceCapabilities struct {
	LanIPChangeSupported bool
	HilinkLoginRequired  bool
	SimState             device.SimState
	Info                 device.Info
}

func ProbeCapabilities(ctx context.Context, d device.Device) (DeviceCapabilities, error) {
	var caps DeviceCapabilities
	login, err := d.LoginRequired(ctx)
	if err != nil {
		return caps, err
	}
	caps.HilinkLoginRequired = login
	if login {
		return caps, ErrLoginProtected
	}
	state, err := d.PinStatus(ctx)
	if err != nil {
		return caps, err
	}
	caps.SimState = state
	if !state.Usable() {
		return caps, fmt.Errorf("%w: pin status %d", ErrSimNotReady, int(state))
	}
	info, err := d.Information(ctx)
	if err != nil {
		return caps, err
	}
	caps.Info = info
	return caps, nil
}
