package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/n4darae/huawei-API/src/internal/config"
	"github.com/n4darae/huawei-API/src/internal/device"
	"github.com/n4darae/huawei-API/src/internal/device/hilink"
	"github.com/n4darae/huawei-API/src/internal/device/sim"
	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/enroll"
	"github.com/n4darae/huawei-API/src/internal/fw"
	"github.com/n4darae/huawei-API/src/internal/netcfg"
	netcfgfake "github.com/n4darae/huawei-API/src/internal/netcfg/fake"
	netcfglinux "github.com/n4darae/huawei-API/src/internal/netcfg/linux"
	"github.com/n4darae/huawei-API/src/internal/proxysup"
	"github.com/n4darae/huawei-API/src/internal/rotate"
	"github.com/n4darae/huawei-API/src/internal/secrets"
	"github.com/n4darae/huawei-API/src/internal/store"
)

var errNotFarmHost = errors.New("this host is not marked as a farm host")

type enrollCmd struct {
	slot          int
	carrier       string
	wait          time.Duration
	rediscover    time.Duration
	sysfs         string
	noUSB         bool
	skipPreflight bool
	skipSelftest  bool
	force         bool
	asJSON        bool
}

func init() {
	c := &enrollCmd{}
	Register(Command{
		Name:  "enroll",
		Usage: "provision one dongle into a slot",
		Flags: c.flags,
		Run:   c.run,
	})
}

func (c *enrollCmd) flags(fs *flag.FlagSet) {
	fs.IntVar(&c.slot, "slot", 0, "slot number 1-150, 0 allocates the lowest free slot")
	fs.StringVar(&c.carrier, "carrier", "", "carrier name recorded on the dongle row")
	fs.DurationVar(&c.wait, "wait", enroll.DefaultLinkWait, "how long to wait for the dongle to enumerate")
	fs.DurationVar(&c.rediscover, "rediscover", enroll.DefaultRediscover, "how long to wait for the dongle at its new lan address")
	fs.StringVar(&c.sysfs, "sysfs", enroll.DefaultSysfsRoot, "sysfs root, for testing against a fixture tree")
	fs.BoolVar(&c.noUSB, "no-usb-guard", false, "do not disable the usb ports of the other un-provisioned slots")
	fs.BoolVar(&c.skipPreflight, "skip-preflight", false, "enrol even though the fatal preflight checks are red")
	fs.BoolVar(&c.skipSelftest, "skip-selftest", false, "do not verify the finished proxy through a real egress probe")
	fs.BoolVar(&c.force, "force", false, "run even though "+config.FarmMarker+" is absent")
	fs.BoolVar(&c.asJSON, "json", false, "emit the result as json")
}

func (c *enrollCmd) run(ctx context.Context, cfg config.Config, args []string) error {
	if runtime.GOOS != "linux" {
		return domain.UnsupportedOn("enroll")
	}
	if err := rejectArgs("enroll", args); err != nil {
		return err
	}
	if c.slot != 0 && !domain.Slot(c.slot).Valid() {
		return fmt.Errorf("enroll: slot %d is outside 1-%d", c.slot, domain.MaxSlots)
	}
	if err := requireFarmHost(cfg, c.force); err != nil {
		return err
	}
	if !cfg.PublicHost.IsValid() {
		return config.ErrPublicHostMissing
	}

	if !c.skipPreflight {
		report := enroll.Preflight(ctx, preflightOptions(cfg))
		if !report.Green(true) {
			fmt.Fprint(os.Stderr, report.FatalFailed().Text())
			return errors.New("enroll: the host is not ready; fix the fatal checks or pass --skip-preflight")
		}
	}

	nc, err := buildNetcfg(cfg)
	if err != nil {
		return err
	}
	if err := nc.EnsureRouteTableNames(ctx); err != nil {
		return err
	}
	if err := nc.EnsureGlobal(ctx, []netip.Addr{cfg.PublicHost}); err != nil {
		return err
	}

	firewall, err := buildFirewall(ctx, cfg)
	if err != nil {
		return err
	}
	devices, closeDevices, err := buildDevices(cfg)
	if err != nil {
		return err
	}
	defer closeDevices()

	repos, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	supervisor, err := buildSupervisor(cfg)
	if err != nil {
		return err
	}

	selftest, closeSelftest, err := buildSelftest(cfg, repos, devices, firewall, c.skipSelftest)
	if err != nil {
		return err
	}
	defer closeSelftest(ctx)

	e, err := enroll.New(enroll.Deps{
		NodeID:          cfg.NodeID,
		PublicHost:      cfg.PublicHost,
		NServerFallback: cfg.NServerFallback,
		Netcfg:          nc,
		Firewall:        firewall,
		Devices:         devices,
		Repos:           repos,
		Supervisor:      supervisor,
		USB:             enroll.NewUSBController(enroll.USBOptions{SysfsRoot: c.sysfs}),
		SkipUSBGuard:    c.noUSB,
		LinkWait:        c.wait,
		Rediscover:      c.rediscover,
		Selftest:        selftest,
		Progress: func(ev enroll.Event) {
			if c.asJSON {
				return
			}
			if ev.Error != "" {
				fmt.Fprintf(os.Stderr, "[%d/%d] %s: %s\n", ev.Index, ev.Total, ev.Step, ev.Error)
				return
			}
			fmt.Printf("[%d/%d] %s: %s\n", ev.Index, ev.Total, ev.Step, ev.Detail)
		},
	})
	if err != nil {
		return err
	}

	res, err := e.Enroll(ctx, enroll.Request{Slot: domain.Slot(c.slot), Carrier: c.carrier})
	if err != nil {
		return err
	}
	if c.asJSON {
		return writeJSON(res)
	}
	printEnrollSummary(cfg, res)
	return nil
}

func buildSelftest(cfg config.Config, repos store.Repos, devices device.Registry, firewall fw.Firewall, skip bool) (enroll.Selftest, func(context.Context), error) {
	if skip {
		return nil, func(context.Context) {}, nil
	}
	prober, err := rotate.NewProber(rotate.ProberOptions{Timeout: cfg.Carrier.VerifyTimeout})
	if err != nil {
		return nil, nil, err
	}
	engine, err := rotate.New(rotate.Deps{
		Repos:  repos,
		Dev:    devices,
		FW:     firewall,
		Probe:  prober,
		NodeID: cfg.NodeID,
	})
	if err != nil {
		return nil, nil, err
	}
	selftest := func(ctx context.Context, proxyID string) error {
		r, err := engine.Selftest(ctx, proxyID)
		if err != nil {
			return err
		}
		if !r.OK() {
			return fmt.Errorf("enroll: selftest failed (%s): socks=%t http=%t egress=%s", r.Error, r.SocksOK, r.HTTPOK, r.EgressIP)
		}
		fmt.Fprintf(os.Stderr, "selftest: socks and http both answered, egress %s in %dms\n", r.EgressIP, r.LatencyMS)
		return nil
	}
	return selftest, func(ctx context.Context) { _ = engine.Shutdown(ctx) }, nil
}

func printEnrollSummary(cfg config.Config, res *enroll.Result) {
	fmt.Println()
	fmt.Printf("slot        %s (%s, uid %d)\n", res.Slot, res.IfName, res.Slot.UID())
	fmt.Printf("device      %s imei %s\n", res.DeviceName, res.IMEI)
	fmt.Printf("iccid       %s\n", res.ICCID)
	fmt.Printf("firmware    %s\n", res.Firmware)
	fmt.Printf("id path     %s\n", res.IDPath)
	fmt.Printf("usb path    %s\n", res.USBPath)
	fmt.Printf("lan ip      %s (change supported: %t)\n", res.LanIP, res.LanIPChangeSupported)
	fmt.Printf("socks5      %s:%d\n", cfg.PublicHost, res.SocksPort)
	fmt.Printf("http        %s:%d\n", cfg.PublicHost, res.HTTPPort)
	fmt.Printf("credentials %s:%s\n", res.Username, res.Password)
	fmt.Printf("operation   %s\n", res.OperationID)
	if !res.SelftestRan {
		fmt.Printf("selftest    NOT RUN: %s\n", res.SelftestNote)
	}
	if !res.LanIPChangeSupported {
		fmt.Printf("\nThis dongle cannot move its LAN subnet. The slot needs the manual\n" +
			"namespace procedure in docs/OPERATIONS.md before it can carry traffic.\n")
	}
	fmt.Printf("\nLabel the physical port %q and plug in the next dongle.\n", res.USBPath)
}

func requireFarmHost(cfg config.Config, force bool) error {
	if force {
		return nil
	}
	marker := cfg.FarmMarkerPath()
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s is absent. This command rewrites ip rules, systemd-networkd files and nft sets in the root network namespace. Create the marker on the real farm host, or pass --force if you are certain", errNotFarmHost, marker)
}

func buildNetcfg(cfg config.Config) (netcfg.Manager, error) {
	switch cfg.Netcfg {
	case config.BackendLinux:
		if runtime.GOOS != "linux" {
			return nil, domain.UnsupportedOn("linux netcfg backend")
		}
		return netcfglinux.New(netcfglinux.Options{
			NetworkDir:    cfg.NetworkDir,
			Exec:          netcfg.SystemExec,
			RequireIDPath: true,
		}), nil
	case config.BackendFake:
		return netcfgfake.New(), nil
	default:
		return nil, fmt.Errorf("%w: netcfg %q", config.ErrBadBackend, string(cfg.Netcfg))
	}
}

func buildFirewall(ctx context.Context, cfg config.Config) (fw.Firewall, error) {
	switch cfg.Firewall {
	case config.BackendNft:
		n := fw.NewNft(fw.Options{})
		if err := n.Verify(ctx); err != nil {
			return nil, err
		}
		return n, nil
	case config.BackendFake:
		return fw.NewFake(), nil
	default:
		return nil, fmt.Errorf("%w: fw %q", config.ErrBadBackend, string(cfg.Firewall))
	}
}

func buildDevices(cfg config.Config) (device.Registry, func(), error) {
	return buildDevicesFor(cfg, true)
}

func buildDevicesFor(cfg config.Config, factoryDefaultLAN bool) (device.Registry, func(), error) {
	switch cfg.Device {
	case config.BackendHiLink:
		r := hilink.NewRegistry(hilink.RegistryOptions{
			Options: hilink.Options{Timeout: hilink.DefaultTimeout},
		})
		return r, func() { r.Close() }, nil
	case config.BackendSim:
		farm := sim.NewFarm(cfg.SimSlots, sim.FarmOptions{FactoryDefaultLAN: factoryDefaultLAN})
		return farm.Registry(), func() { farm.Close() }, nil
	default:
		return nil, nil, fmt.Errorf("%w: device %q", config.ErrBadBackend, string(cfg.Device))
	}
}

func buildSupervisor(cfg config.Config) (proxysup.Supervisor, error) {
	switch cfg.Proxy {
	case config.BackendSystemd:
		return proxysup.NewSystemd(proxysup.Options{
			Bin:        cfg.Bin3proxy,
			LogDir:     cfg.LogDir,
			InternalIP: cfg.PublicHost,
		})
	case config.BackendFake:
		return nil, fmt.Errorf("%w: the fake proxy backend cannot enrol a real slot", domain.ErrNotImplemented)
	default:
		return nil, fmt.Errorf("%w: proxy %q", config.ErrBadBackend, string(cfg.Proxy))
	}
}

func openStore(ctx context.Context, cfg config.Config) (store.Repos, func(), error) {
	sealer, err := loadSealer(cfg)
	if err != nil {
		return nil, nil, err
	}
	s, err := store.Open(cfg.DBPath, sealer)
	if err != nil {
		return nil, nil, err
	}
	if err := s.Migrate(ctx); err != nil {
		s.Close()
		return nil, nil, err
	}
	if err := ensureNode(ctx, s, cfg); err != nil {
		s.Close()
		return nil, nil, err
	}
	return s, func() { s.Close() }, nil
}

func loadSealer(cfg config.Config) (secrets.Sealer, error) {
	if dir, ok := os.LookupEnv("CREDENTIALS_DIRECTORY"); ok {
		if sealer, err := secrets.LoadKEK(dir + "/" + config.KEKCredName); err == nil {
			return sealer, nil
		}
	}
	sealer, err := secrets.LoadKEK(kekPath(cfg))
	if errors.Is(err, secrets.ErrKEKMissing) {
		return nil, fmt.Errorf("%w. On a fresh host run `%s bootstrap-kek`; on an existing one restore the copy you took off the machine, because nothing else can decrypt the stored passwords", err, config.Product)
	}
	return sealer, err
}

func kekPath(cfg config.Config) string {
	return strings.TrimSuffix(cfg.EtcDir, "/") + "/kek.cred"
}

func ensureNode(ctx context.Context, s *store.Store, cfg config.Config) error {
	_, err := s.Nodes().Get(ctx, cfg.NodeID)
	if err == nil {
		return nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	now := time.Now().UnixMilli()
	return s.Nodes().Upsert(ctx, domain.Node{
		ID:         cfg.NodeID,
		Name:       cfg.NodeName,
		Kind:       domain.NodeKindLocal,
		PublicHost: cfg.PublicHost,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
}
