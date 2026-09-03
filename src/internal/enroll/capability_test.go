package enroll

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/n4darae/huawei-API/src/internal/config"
	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/netcfg"
	"github.com/n4darae/huawei-API/src/internal/proxysup"
)

var testPublic = netip.MustParseAddr("203.0.113.7")

const staticAddrOutput = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n" +
	"2: enp1s0f0    inet 203.0.113.7/24 brd 203.0.113.255 scope global enp1s0f0\\       valid_lft forever preferred_lft forever\n"

const leasedAddrOutput = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n" +
	"2: enp1s0f0    inet 203.0.113.7/24 metric 100 brd 203.0.113.255 scope global dynamic enp1s0f0\\       valid_lft 75445sec preferred_lft 75445sec\n"

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func greenOptions(t *testing.T) PreflightOptions {
	t.Helper()
	root := t.TempDir()

	binDir := filepath.Join(root, "lib")
	bin := filepath.Join(binDir, "3proxy")
	writeFile(t, bin, "#!/bin/true\n", 0o755)
	sum, err := FileSHA256(bin)
	if err != nil {
		t.Fatalf("FileSHA256: %v", err)
	}
	writeFile(t, PinPath(binDir), Pin{SHA256: sum, Commit: config.Pin3proxyCommit}.String()+"\n", 0o644)

	proc := filepath.Join(root, "proc")
	writeFile(t, filepath.Join(proc, "sys/net/ipv4/conf/all/rp_filter"), "2\n", 0o644)
	writeFile(t, filepath.Join(proc, "sys/net/ipv4/ip_forward"), "0\n", 0o644)

	udev := filepath.Join(root, "udev")
	writeFile(t, filepath.Join(udev, UdevRuleName), "# ignore\n", 0o644)

	rtTables := filepath.Join(root, "rt_tables.d")
	if err := os.MkdirAll(rtTables, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	groupFile := filepath.Join(root, "group")
	writeFile(t, groupFile, "root:x:0:\nnogroup:x:65534:\ndongled:x:6100:\n", 0o644)

	backups := filepath.Join(root, "backups")
	writeFile(t, filepath.Join(backups, config.Product+"-20260808T101500Z.db"), "sqlite", 0o600)

	return PreflightOptions{
		Bin3proxy:    bin,
		BinDir:       binDir,
		BackupDir:    backups,
		GroupFile:    groupFile,
		ProcRoot:     proc,
		RtTablesDir:  rtTables,
		UdevRuleDirs: []string{udev},
		PublicHosts:  []netip.Addr{testPublic},
		Slots:        domain.Slots(),
		Exec: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte(staticAddrOutput), nil
		},
		ReadRules: func(context.Context) ([]netcfg.RuleState, error) {
			return []netcfg.RuleState{
				{Priority: 0, Table: 255, Raw: "from all lookup local"},
				{Priority: domain.RulePrioPublic, Table: 254, IifName: "lo",
					Src: netip.PrefixFrom(testPublic, 32), Raw: "from 203.0.113.7 iif lo lookup main"},
				{Priority: 1001, Table: 1001, Src: netip.MustParsePrefix("192.168.101.100/32")},
				{Priority: 5210, Table: 254, Raw: "from all fwmark 0x80000/0xff0000 lookup main"},
				{Priority: 32766, Table: 254, Raw: "from all lookup main"},
			}, nil
		},
		HasListener:   func(netip.Addr, int) (bool, error) { return false, nil },
		Conntrack:     func() (int, error) { return 128, nil },
		VerifyNft:     func(context.Context) error { return nil },
		KernelRelease: func() (string, error) { return "6.2.0-39-generic", nil },
		UnitEnabled:   func(context.Context, string) (string, error) { return "enabled", nil },
		Now:           time.Now(),
	}
}

func byName(r Report, name string) Check {
	for _, c := range r {
		if c.Name == name {
			return c
		}
	}
	return Check{Name: name, Detail: "check not produced"}
}

func TestPreflightIsGreenOnAFullyPreparedHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the executable bit checkBinary reads does not exist in a windows os.FileMode")
	}
	r := Preflight(context.Background(), greenOptions(t))
	if len(r) != 14 {
		t.Fatalf("preflight produced %d checks, want 14:\n%s", len(r), r.Text())
	}
	if !r.Green(false) {
		t.Fatalf("a fully prepared host must be green:\n%s", r.Text())
	}
	if !r.Green(true) {
		t.Fatalf("fatal-only must also be green:\n%s", r.Text())
	}
}

func TestPreflightTurnsRedOnExactlyTheBrokenItem(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the executable bit checkBinary reads does not exist in a windows os.FileMode")
	}
	cases := []struct {
		name    string
		check   string
		fatal   bool
		mutate  func(t *testing.T, o *PreflightOptions)
		wantHas string
	}{
		{
			name:  "3proxy binary missing",
			check: CheckBinary, fatal: true,
			mutate:  func(t *testing.T, o *PreflightOptions) { os.Remove(o.Bin3proxy) },
			wantHas: config.Pin3proxyCommit,
		},
		{
			name:  "3proxy binary does not match the pin",
			check: CheckBinary, fatal: true,
			mutate: func(t *testing.T, o *PreflightOptions) {
				writeFile(t, o.Bin3proxy, "#!/bin/false\n", 0o755)
			},
			wantHas: "pin record says",
		},
		{
			name:  "pin record names a different commit",
			check: CheckBinary, fatal: true,
			mutate: func(t *testing.T, o *PreflightOptions) {
				sum, _ := FileSHA256(o.Bin3proxy)
				writeFile(t, PinPath(o.BinDir), Pin{SHA256: sum, Commit: "deadbeef"}.String(), 0o644)
			},
			wantHas: "deadbeef",
		},
		{
			name:  "conntrack netlink is unavailable",
			check: CheckConntrack, fatal: true,
			mutate: func(t *testing.T, o *PreflightOptions) {
				o.Conntrack = func() (int, error) { return 0, errors.New("protocol not supported") }
			},
			wantHas: "NETLINK_NETFILTER",
		},
		{
			name:  "ModemManager is enabled and unfenced",
			check: CheckModemManager, fatal: true,
			mutate: func(t *testing.T, o *PreflightOptions) {
				os.Remove(filepath.Join(o.UdevRuleDirs[0], UdevRuleName))
			},
			wantHas: "claim every dongle netdev",
		},
		{
			name:  "rt_tables.d missing",
			check: CheckRtTables, fatal: true,
			mutate:  func(t *testing.T, o *PreflightOptions) { os.RemoveAll(o.RtTablesDir) },
			wantHas: "does not exist",
		},
		{
			name:  "rp_filter is strict",
			check: CheckRpFilter, fatal: true,
			mutate: func(t *testing.T, o *PreflightOptions) {
				writeFile(t, filepath.Join(o.ProcRoot, "sys/net/ipv4/conf/all/rp_filter"), "1\n", 0o644)
			},
			wantHas: "must be 2",
		},
		{
			name:  "ip_forward is on",
			check: CheckIPForward, fatal: true,
			mutate: func(t *testing.T, o *PreflightOptions) {
				writeFile(t, filepath.Join(o.ProcRoot, "sys/net/ipv4/ip_forward"), "1\n", 0o644)
			},
			wantHas: "must be 0",
		},
		{
			name:  "a foreign rule evaluates before 900",
			check: CheckForeignRule, fatal: true,
			mutate: func(t *testing.T, o *PreflightOptions) {
				prev := o.ReadRules
				o.ReadRules = func(ctx context.Context) ([]netcfg.RuleState, error) {
					rules, _ := prev(ctx)
					return append(rules, netcfg.RuleState{Priority: 100, Table: 42, Raw: "from all lookup 42"}), nil
				}
			},
			wantHas: "100:",
		},
		{
			name:  "the priority 900 rule is missing",
			check: CheckPublicRule, fatal: true,
			mutate: func(t *testing.T, o *PreflightOptions) {
				o.ReadRules = func(context.Context) ([]netcfg.RuleState, error) {
					return []netcfg.RuleState{{Priority: 32766, Table: 254}}, nil
				}
			},
			wantHas: "iif lo lookup main priority 900",
		},
		{
			name:  "a reserved port is taken",
			check: CheckPortsFree, fatal: false,
			mutate: func(t *testing.T, o *PreflightOptions) {
				o.HasListener = func(_ netip.Addr, p int) (bool, error) {
					return p == config.SocksPortBase+3, nil
				}
			},
			wantHas: "21003",
		},
		{
			name:  "group dongled is absent",
			check: CheckGroup, fatal: true,
			mutate: func(t *testing.T, o *PreflightOptions) {
				writeFile(t, o.GroupFile, "root:x:0:\n", 0o644)
			},
			wantHas: "systemd-sysusers",
		},
		{
			name:  "group dongled has the wrong gid",
			check: CheckGroup, fatal: true,
			mutate: func(t *testing.T, o *PreflightOptions) {
				writeFile(t, o.GroupFile, "dongled:x:1234:\n", 0o644)
			},
			wantHas: "nft egress chain matches gid 6100",
		},
		{
			name:  "the nft table is absent",
			check: CheckNftTable, fatal: true,
			mutate: func(t *testing.T, o *PreflightOptions) {
				o.VerifyNft = func(context.Context) error { return errors.New("no such table") }
			},
			wantHas: "inet dongled",
		},
		{
			name:  "the public address is a dhcp lease",
			check: CheckStaticAddr, fatal: false,
			mutate: func(t *testing.T, o *PreflightOptions) {
				o.Exec = func(context.Context, string, ...string) ([]byte, error) {
					return []byte(leasedAddrOutput), nil
				}
			},
			wantHas: "DHCP lease",
		},
		{
			name:  "the kernel is too old to rename a live interface",
			check: CheckKernel, fatal: true,
			mutate: func(t *testing.T, o *PreflightOptions) {
				o.KernelRelease = func() (string, error) { return "6.1.0-18-amd64", nil }
			},
			wantHas: "EBUSY",
		},
		{
			name:  "there is no recent backup",
			check: CheckBackup, fatal: false,
			mutate: func(t *testing.T, o *PreflightOptions) {
				o.Now = time.Now().Add(30 * 24 * time.Hour)
			},
			wantHas: "old, limit is",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := greenOptions(t)
			tc.mutate(t, &o)
			r := Preflight(context.Background(), o)

			got := byName(r, tc.check)
			if got.OK {
				t.Fatalf("%s stayed green:\n%s", tc.check, r.Text())
			}
			if got.Fatal != tc.fatal {
				t.Fatalf("%s reports Fatal=%v, want %v", tc.check, got.Fatal, tc.fatal)
			}
			if !strings.Contains(got.Detail, tc.wantHas) {
				t.Fatalf("%s detail %q does not mention %q", tc.check, got.Detail, tc.wantHas)
			}
			for _, other := range r {
				if other.Name != tc.check && !other.OK {
					t.Fatalf("%s also went red as collateral: %s", other.Name, other.Detail)
				}
			}
			if r.Green(false) {
				t.Fatalf("the report must not be green")
			}
			if r.Green(true) != !tc.fatal {
				t.Fatalf("fatal-only greenness is %v for a Fatal=%v failure", r.Green(true), tc.fatal)
			}
		})
	}
}

func TestKernelVersionGate(t *testing.T) {
	cases := []struct {
		release string
		want    bool
	}{
		{"7.0.0-28-generic", true},
		{"6.2.0-39-generic", true},
		{"6.11.0-9-generic", true},
		{"6.1.0-18-amd64", false},
		{"5.15.0-105-generic", false},
		{"6.2", true},
	}
	for _, c := range cases {
		got, err := KernelAtLeast(c.release, MinKernelMajor, MinKernelMinor)
		if err != nil {
			t.Fatalf("KernelAtLeast(%q): %v", c.release, err)
		}
		if got != c.want {
			t.Fatalf("KernelAtLeast(%q) = %v, want %v", c.release, got, c.want)
		}
	}
	if _, _, err := ParseKernelRelease("banana"); err == nil {
		t.Fatalf("an unparsable release must be an error, not a silent pass")
	}
}

func TestParsePinNeedsBothHalves(t *testing.T) {
	p, err := ParsePin("sha256:abc123 commit:" + config.Pin3proxyCommit)
	if err != nil {
		t.Fatalf("ParsePin: %v", err)
	}
	if p.SHA256 != "abc123" || p.Commit != config.Pin3proxyCommit {
		t.Fatalf("ParsePin round trip gave %+v", p)
	}
	for _, bad := range []string{"", "sha256:abc", "commit:abc", "abc123"} {
		if _, err := ParsePin(bad); err == nil {
			t.Fatalf("ParsePin(%q) must fail", bad)
		}
	}
}

func deployFile(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", rel))
	if err != nil {
		t.Fatalf("read deploy/%s: %v", rel, err)
	}
	return string(raw)
}

func TestDeployedProxyUnitIsExactlyWhatTheSupervisorRenders(t *testing.T) {
	want := proxysup.RenderUnit(proxysup.UnitOptions{
		Bin:     "/usr/local/lib/dongled/3proxy",
		ConfDir: "/etc/dongled/proxy",
		LogDir:  "/var/log/dongled",
	})
	got := deployFile(t, "dongled-proxy@.service")
	if !bytes.Equal([]byte(got), want) {
		t.Fatalf("deploy/dongled-proxy@.service has drifted from proxysup.RenderUnit; regenerate it instead of hand editing\n--- on disk ---\n%s\n--- rendered ---\n%s", got, want)
	}
	for _, must := range []string{
		"RestrictAddressFamilies=AF_INET AF_UNIX\n",
		"Group=" + config.GroupName + "\n",
		"ExecReload=/bin/kill -USR1 $MAINPID\n",
	} {
		if !strings.Contains(got, must) {
			t.Fatalf("dongled-proxy@.service lost %q", strings.TrimSpace(must))
		}
	}
	if strings.Contains(got, "SystemCallFilter") {
		t.Fatalf("a SystemCallFilter blocks setuid and reproduces the zero-listener failure")
	}
	if strings.Contains(got, "AF_NETLINK") {
		t.Fatalf("the proxy instances have no business on netlink")
	}
}

func TestBackendUnitKeepsItsLoadBearingDirectives(t *testing.T) {
	unit := deployFile(t, "dongled.service")
	for _, must := range []string{
		"Type=notify",
		"RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK",
		"AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW",
		"ProtectSystem=strict",
		"ReadWritePaths=/etc/systemd/network",
		"ReadWritePaths=/etc/iproute2/rt_tables.d",
		"preflight --fatal-only",
	} {
		if !strings.Contains(unit, must) {
			t.Fatalf("dongled.service is missing %q", must)
		}
	}
	for _, line := range strings.Split(unit, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "Group=") || strings.HasPrefix(trimmed, "SupplementaryGroups=") {
			t.Fatalf("dongled.service must not join a group: %q. gid %d has its egress dropped by the nft chain and every health probe times out silently", trimmed, config.GroupGID)
		}
	}
	if strings.Contains(unit, "ProtectKernelTunables=yes") {
		t.Fatalf("ProtectKernelTunables hides /proc/sys, which netcfg reads to assert rp_filter")
	}
}

func TestNetworkdDropInStopsNetworkdFromEatingRule900(t *testing.T) {
	conf := deployFile(t, "networkd.conf.d/dongled.conf")
	if !strings.Contains(conf, "ManageForeignRoutingPolicyRules=no") {
		t.Fatalf("without ManageForeignRoutingPolicyRules=no, networkctl reconfigure deletes the priority %d rule and every customer connection dies", domain.RulePrioPublic)
	}
	if !strings.Contains(conf, "[Network]") {
		t.Fatalf("the setting only takes effect inside the [Network] section")
	}
}

func TestSysctlDropInStaysOutOfSharedGlobals(t *testing.T) {
	conf := deployFile(t, "sysctl.d/60-"+config.Product+".conf")
	if !strings.Contains(conf, "net.ipv4.conf.default.rp_filter = 2") {
		t.Fatalf("the drop-in must set rp_filter through the default. prefix")
	}
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "net.ipv4.conf.all.") {
			t.Fatalf("conf.all.* is shared with every other service on the host: %q", trimmed)
		}
		if strings.Contains(trimmed, "tcp_retries2") {
			t.Fatalf("tcp_retries2 is a host-wide change and belongs in the OPERATIONS.md opt-in procedure, not in an installer")
		}
	}
}

func TestNginxDropInKeepsSSEUnbuffered(t *testing.T) {
	conf := deployFile(t, "nginx/conf.d/"+config.Product+"-limits.conf")
	for _, must := range []string{"limit_req_zone", "proxy_buffering    off", "/api/v1/events"} {
		if !strings.Contains(conf, must) {
			t.Fatalf("nginx drop-in is missing %q; SSE dies on day one with nothing in the logs", must)
		}
	}
	if strings.Contains(conf, "include /etc/nginx/nginx.conf") {
		t.Fatalf("nginx.conf is never ours to touch")
	}
}

func TestSysusersGivesEverySlotItsOwnUid(t *testing.T) {
	conf := deployFile(t, "sysusers.d/"+config.Product+".conf")
	if !strings.Contains(conf, fmt.Sprintf("g %s %d", config.GroupName, config.GroupGID)) {
		t.Fatalf("sysusers.d must create group %s with gid %d", config.GroupName, config.GroupGID)
	}
	for _, s := range domain.Slots() {
		want := fmt.Sprintf("u %s %d:%d ", s.UserName(), s.UID(), config.GroupGID)
		if !strings.Contains(conf, want) {
			t.Fatalf("sysusers.d is missing %q", want)
		}
	}
}

func TestPreflightSkipsTheChecksASimulatedBackendCannotSatisfy(t *testing.T) {
	o := PreflightOptions{
		SkipNetcfg:   true,
		SkipFirewall: true,
		SkipProxy:    true,
		SkipDevice:   true,
	}
	report := Preflight(context.Background(), o)

	byName := map[string]Check{}
	for _, c := range report {
		byName[c.Name] = c
	}
	for _, name := range []string{
		CheckBinary, CheckConntrack, CheckModemManager, CheckRtTables, CheckRpFilter,
		CheckIPForward, CheckForeignRule, CheckPublicRule, CheckGroup, CheckNftTable,
		CheckStaticAddr, CheckKernel,
	} {
		c, ok := byName[name]
		if !ok {
			t.Fatalf("%s is missing from the report", name)
		}
		if !c.Skipped {
			t.Errorf("%s ran against a simulated backend: %+v", name, c)
		}
		if !c.OK {
			t.Errorf("%s is skipped but still counts as a failure: %+v", name, c)
		}
	}
	if c := byName[CheckPortsFree]; c.Skipped {
		t.Error("the listener ports are real whatever the backends are")
	}
	if len(report.FatalFailed()) != 0 {
		t.Errorf("a fully simulated host still has fatal failures: %v", report.FatalFailed())
	}
}
