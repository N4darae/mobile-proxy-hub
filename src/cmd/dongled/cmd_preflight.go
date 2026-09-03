package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strings"

	"github.com/n4darae/huawei-API/src/internal/config"
	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/enroll"
)

type preflightCmd struct {
	fatalOnly bool
	asJSON    bool
	quiet     bool
}

func init() {
	c := &preflightCmd{}
	Register(Command{
		Name:  "preflight",
		Usage: "check host readiness, read only",
		Flags: c.flags,
		Run:   c.run,
	})
}

func (c *preflightCmd) flags(fs *flag.FlagSet) {
	fs.BoolVar(&c.fatalOnly, "fatal-only", false, "exit non-zero only when a fatal check fails")
	fs.BoolVar(&c.asJSON, "json", false, "emit the report as json")
	fs.BoolVar(&c.quiet, "quiet", false, "print nothing, report through the exit code")
}

func (c *preflightCmd) run(ctx context.Context, cfg config.Config, args []string) error {
	if runtime.GOOS != "linux" {
		return domain.UnsupportedOn("preflight")
	}
	if err := rejectArgs("preflight", args); err != nil {
		return err
	}

	report := enroll.Preflight(ctx, preflightOptions(cfg))

	switch {
	case c.quiet:
	case c.asJSON:
		if err := writeJSON(report); err != nil {
			return err
		}
	default:
		fmt.Print(report.Text())
	}

	if report.Green(c.fatalOnly) {
		return nil
	}
	failed := report.Failed()
	if c.fatalOnly {
		failed = report.FatalFailed()
	}
	names := make([]string, 0, len(failed))
	for _, ch := range failed {
		names = append(names, ch.Name)
	}
	return fmt.Errorf("preflight: %d check(s) failed: %s", len(failed), strings.Join(names, ", "))
}

func preflightOptions(cfg config.Config) enroll.PreflightOptions {
	o := enroll.PreflightOptions{
		Bin3proxy:    cfg.Bin3proxy,
		BinDir:       cfg.BinDir,
		BackupDir:    cfg.BackupDir,
		PanelAddr:    cfg.PanelAddr,
		MetricsAddr:  cfg.MetricsAddr,
		SkipNetcfg:   cfg.Netcfg == config.BackendFake,
		SkipFirewall: cfg.Firewall == config.BackendFake,
		SkipProxy:    cfg.Proxy == config.BackendFake,
		SkipDevice:   cfg.Device == config.BackendSim,
	}
	if cfg.PublicHost.IsValid() {
		o.PublicHosts = []netip.Addr{cfg.PublicHost}
	}
	return o
}

func rejectArgs(name string, args []string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("%s: unexpected argument %q", name, args[0])
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
