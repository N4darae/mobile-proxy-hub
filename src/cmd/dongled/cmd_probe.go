package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/n4darae/huawei-API/src/internal/config"
	"github.com/n4darae/huawei-API/src/internal/device"
	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/enroll"
	"github.com/n4darae/huawei-API/src/internal/netcfg"
)

const (
	ExperimentA2    = "a2"
	ExperimentA3    = "a3"
	ExperimentA4    = "a4"
	ExperimentA6    = "a6"
	ExperimentLogin = "login"

	A3DefaultRounds = 20
	A4SettleWait    = 60 * time.Second
	A3GateRate      = 0.70
)

func A3Ladder() []time.Duration {
	return []time.Duration{2 * time.Second, 6 * time.Second, 15 * time.Second, 40 * time.Second}
}

type probeCmd struct {
	experiment string
	slot       int
	addr       string
	iface      string
	rounds     int
	sysfs      string
	out        string
	jsonOut    string
	asJSON     bool
}

func init() {
	c := &probeCmd{}
	Register(Command{
		Name:  "probe",
		Usage: "run a hardware measurement (--experiment a2|a3|a4|a6|login)",
		Flags: c.flags,
		Run:   c.run,
	})
}

func (c *probeCmd) flags(fs *flag.FlagSet) {
	fs.StringVar(&c.experiment, "experiment", "", "a2|a3|a4|a6|login")
	fs.IntVar(&c.slot, "slot", 0, "talk to the dongle enrolled in this slot")
	fs.StringVar(&c.addr, "addr", "", "talk to the dongle at this address, defaults to "+device.FactoryDefaultAddr.String())
	fs.StringVar(&c.iface, "iface", "", "netdev to sample, defaults to the slot interface")
	fs.IntVar(&c.rounds, "rounds", A3DefaultRounds, "rotations per hold step for a3")
	fs.StringVar(&c.sysfs, "sysfs", enroll.DefaultSysfsRoot, "sysfs root")
	fs.StringVar(&c.out, "out", "", "append a markdown section to this file, typically docs/OPERATIONS.md")
	fs.StringVar(&c.jsonOut, "json-out", "", "write the machine readable result to this file")
	fs.BoolVar(&c.asJSON, "json", false, "print json instead of markdown")
}

type fact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
}

type holdResult struct {
	HoldSeconds float64  `json:"hold_seconds"`
	Attempts    int      `json:"attempts"`
	Changed     int      `json:"ip_changed"`
	Unchanged   int      `json:"ip_unchanged"`
	Errors      int      `json:"errors"`
	Rate        float64  `json:"change_rate"`
	MedianMS    int64    `json:"median_ms"`
	MaxMS       int64    `json:"max_ms"`
	Addresses   []string `json:"addresses"`
}

type probeReport struct {
	Experiment string           `json:"experiment"`
	StartedAt  time.Time        `json:"started_at"`
	DurationMS int64            `json:"duration_ms"`
	Host       string           `json:"host"`
	Kernel     string           `json:"kernel"`
	Target     string           `json:"target,omitempty"`
	Gates      string           `json:"gates"`
	Verdict    string           `json:"verdict"`
	Facts      []fact           `json:"facts"`
	Ladder     []holdResult     `json:"hold_ladder,omitempty"`
	Samples    []map[string]any `json:"samples,omitempty"`
}

func experimentNeedsSysfs(exp string) bool {
	switch exp {
	case ExperimentA2, ExperimentA4, ExperimentA6:
		return true
	}
	return false
}

func (c *probeCmd) run(ctx context.Context, cfg config.Config, args []string) error {
	if err := rejectArgs("probe", args); err != nil {
		return err
	}

	started := time.Now()
	kernel, _ := enroll.KernelRelease()
	host, _ := os.Hostname()
	rep := probeReport{
		Experiment: strings.ToLower(c.experiment),
		StartedAt:  started.UTC(),
		Host:       host,
		Kernel:     kernel,
	}

	if runtime.GOOS != "linux" && experimentNeedsSysfs(rep.Experiment) {
		return domain.UnsupportedOn("probe " + rep.Experiment)
	}

	var err error
	switch rep.Experiment {
	case ExperimentA6:
		err = probeA6(ctx, cfg, c.sysfs, &rep)
	case ExperimentA4:
		err = probeA4(ctx, cfg, c.sysfs, c.iface, domain.Slot(c.slot), &rep)
	case ExperimentLogin:
		err = probeLogin(ctx, cfg, c.addr, domain.Slot(c.slot), &rep)
	case ExperimentA2:
		err = probeA2(ctx, cfg, c.addr, domain.Slot(c.slot), c.sysfs, &rep)
	case ExperimentA3:
		err = probeA3(ctx, cfg, c.addr, domain.Slot(c.slot), c.rounds, &rep)
	case "":
		return errors.New("probe: --experiment is required, one of a2, a3, a4, a6, login")
	default:
		return fmt.Errorf("probe: unknown experiment %q", c.experiment)
	}
	rep.DurationMS = time.Since(started).Milliseconds()
	if err != nil {
		rep.Verdict = "ABORTED: " + err.Error()
	}

	if c.jsonOut != "" {
		if werr := writeJSONFile(c.jsonOut, rep); werr != nil {
			return werr
		}
	}
	if c.out != "" {
		if werr := appendMarkdown(c.out, rep); werr != nil {
			return werr
		}
		fmt.Fprintf(os.Stderr, "appended to %s\n", c.out)
	}
	if c.asJSON {
		if jerr := writeJSON(rep); jerr != nil {
			return jerr
		}
	} else {
		fmt.Print(renderMarkdown(rep))
	}
	return err
}

func probeDevice(ctx context.Context, cfg config.Config, addr string, slot domain.Slot) (device.Device, func(), string, error) {
	devices, closeDevices, err := buildDevices(cfg)
	if err != nil {
		return nil, nil, "", err
	}
	target := device.FactoryDefaultAddr
	switch {
	case addr != "":
		a, perr := netip.ParseAddr(addr)
		if perr != nil {
			closeDevices()
			return nil, nil, "", perr
		}
		target = a
	case slot.Valid():
		target = slot.GatewayIP()
	}
	d, err := devices.ForAddr(ctx, target)
	if err != nil {
		closeDevices()
		return nil, nil, "", err
	}
	return d, closeDevices, target.String(), nil
}

func probeLogin(ctx context.Context, cfg config.Config, addr string, slot domain.Slot, rep *probeReport) error {
	d, done, target, err := probeDevice(ctx, cfg, addr, slot)
	if err != nil {
		return err
	}
	defer done()
	rep.Target = target
	rep.Gates = "P1 error handling, and whether enrollment is allowed to refuse a dongle outright"

	if !d.Reachable(ctx) {
		return fmt.Errorf("no HiLink API answers at %s", target)
	}
	login, err := d.LoginRequired(ctx)
	if err != nil {
		return err
	}
	info, err := d.Information(ctx)
	if err != nil {
		return err
	}
	state, err := d.PinStatus(ctx)
	if err != nil {
		return err
	}
	rep.Facts = []fact{
		{Name: "device_name", Value: info.DeviceName, Note: "the SKU string; -320 and -325 differ in firmware, not in this API"},
		{Name: "hardware_version", Value: info.HardwareVersion},
		{Name: "software_version", Value: info.SoftwareVersion},
		{Name: "webui_version", Value: info.WebUIVersion},
		{Name: "imei", Value: info.IMEI},
		{Name: "iccid", Value: info.ICCID},
		{Name: "hilink_login_required", Value: strconv.FormatBool(login),
			Note: "true means every POST fails with 100003 until Require login is switched off in the web UI"},
		{Name: "pin_status", Value: fmt.Sprintf("%d (%s)", int(state), enroll.SimStateText(state))},
	}
	if login {
		rep.Verdict = "REFUSE: this dongle is password protected. Enrollment must stop and say so."
		return nil
	}
	rep.Verdict = "OK: no password, the whole no-RSA-login design holds for this SKU."
	return nil
}

func probeA6(ctx context.Context, cfg config.Config, sysfs string, rep *probeReport) error {
	rep.Gates = "whether this machine can be the farm host at all"

	report := enroll.Preflight(ctx, preflightOptions(cfg))
	for _, name := range []string{enroll.CheckKernel, enroll.CheckStaticAddr, enroll.CheckRpFilter, enroll.CheckRtTables} {
		for _, c := range report {
			if c.Name != name {
				continue
			}
			rep.Facts = append(rep.Facts, fact{Name: c.Name, Value: passFail(c.OK), Note: c.Detail})
		}
	}

	hubs, hubErr := probeHubs(ctx, cfg)
	if hubErr != nil {
		rep.Facts = append(rep.Facts, fact{Name: "hub_ppps", Value: "UNKNOWN",
			Note: "uhubctl did not run (" + hubErr.Error() + "). Install uhubctl; without per-port power switching a wedged dongle can only be recovered by hand."})
	} else if len(hubs) == 0 {
		rep.Facts = append(rep.Facts, fact{Name: "hub_ppps", Value: "NONE",
			Note: "uhubctl found no hub with per-port power switching. Any hub you buy must advertise PPPS."})
	} else {
		for _, h := range hubs {
			rep.Facts = append(rep.Facts, fact{Name: "hub_ppps", Value: h.name, Note: h.detail})
		}
	}

	ctl := enroll.NewUSBController(enroll.USBOptions{SysfsRoot: sysfs})
	nets, err := ctl.USBNets()
	if err == nil {
		var lines []string
		for _, n := range nets {
			lines = append(lines, fmt.Sprintf("%s=%s", n.Iface, n.Device))
		}
		rep.Facts = append(rep.Facts, fact{Name: "usb_netdevs", Value: strconv.Itoa(len(nets)), Note: strings.Join(lines, " ")})
	}
	if budget := powerBudget(sysfs); budget != "" {
		rep.Facts = append(rep.Facts, fact{Name: "bMaxPower", Value: budget,
			Note: "an E3372 draws close to 1A while transmitting; a hub that advertises 2A total browns out at the fourth dongle"})
	}

	blockers := 0
	for _, f := range rep.Facts {
		if f.Value == "FAIL" || f.Value == "NONE" {
			blockers++
		}
	}
	if blockers == 0 {
		rep.Verdict = "OK: this host can carry a farm."
		return nil
	}
	rep.Verdict = fmt.Sprintf("NOT READY: %d blocking item(s). See docs/HARDWARE.md.", blockers)
	return nil
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

type hubInfo struct{ name, detail string }

func probeHubs(ctx context.Context, cfg config.Config) ([]hubInfo, error) {
	out, err := netcfg.SystemExec(ctx, "uhubctl")
	if err != nil && len(out) == 0 {
		return nil, err
	}
	var hubs []hubInfo
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Current status for hub ") {
			continue
		}
		if !strings.Contains(trimmed, "ppps") {
			continue
		}
		rest := strings.TrimPrefix(trimmed, "Current status for hub ")
		name, detail, _ := strings.Cut(rest, " ")
		hubs = append(hubs, hubInfo{name: name, detail: strings.Trim(detail, "[]")})
	}
	return hubs, nil
}

func powerBudget(sysfs string) string {
	entries, err := os.ReadDir(filepath.Join(sysfs, "bus", "usb", "devices"))
	if err != nil {
		return ""
	}
	var parts []string
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(sysfs, "bus", "usb", "devices", e.Name(), "bMaxPower"))
		if err != nil {
			continue
		}
		v := strings.TrimSpace(string(raw))
		if v == "" || v == "0mA" {
			continue
		}
		parts = append(parts, e.Name()+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

func probeA4(ctx context.Context, cfg config.Config, sysfs, iface string, slot domain.Slot, rep *probeReport) error {
	if iface == "" {
		if !slot.Valid() {
			return errors.New("probe a4: pass --iface or --slot")
		}
		iface = slot.IfaceName()
	}
	rep.Target = iface
	rep.Gates = "ConfigureWithoutCarrier, the definition of \"present\", and the rotate PreCheck"

	sample := func(label string) map[string]any {
		s := map[string]any{"at": time.Now().UTC().Format(time.RFC3339), "label": label}
		for _, attr := range []string{"carrier", "operstate", "flags", "mtu", "address"} {
			raw, err := os.ReadFile(filepath.Join(sysfs, "class", "net", iface, attr))
			if err != nil {
				s[attr] = "ERR: " + err.Error()
				continue
			}
			s[attr] = strings.TrimSpace(string(raw))
		}
		return s
	}

	first := sample("immediately after enumeration")
	rep.Samples = append(rep.Samples, first)
	fmt.Fprintf(os.Stderr, "sampled %s, waiting %s for the second sample\n", iface, A4SettleWait)
	if err := domain.SystemClock().Sleep(ctx, A4SettleWait); err != nil {
		return err
	}
	second := sample("60 seconds later")
	rep.Samples = append(rep.Samples, second)

	rep.Facts = []fact{
		{Name: "carrier_t0", Value: fmt.Sprint(first["carrier"])},
		{Name: "operstate_t0", Value: fmt.Sprint(first["operstate"])},
		{Name: "carrier_t60", Value: fmt.Sprint(second["carrier"])},
		{Name: "operstate_t60", Value: fmt.Sprint(second["operstate"])},
	}
	if fmt.Sprint(second["carrier"]) == "1" && fmt.Sprint(second["operstate"]) == netcfg.OperStateUp {
		rep.Verdict = "This SKU reports a real carrier. \"present\" may use it as a hint, but the HiLink API answering stays the definition."
		return nil
	}
	rep.Verdict = "carrier/operstate are NOT trustworthy on this SKU. Keep ConfigureWithoutCarrier=yes, IgnoreCarrierLoss=yes, and keep \"present\" defined as \"the HiLink API answers\"."
	return nil
}

func probeA2(ctx context.Context, cfg config.Config, addr string, slot domain.Slot, sysfs string, rep *probeReport) error {
	if !slot.Valid() {
		return errors.New("probe a2: --slot is required, it names the subnet to move to")
	}
	d, done, target, err := probeDevice(ctx, cfg, addr, 0)
	if err != nil {
		return err
	}
	defer done()
	rep.Target = target
	rep.Gates = "flat policy routing vs a network namespace per dongle. A failure here means P2 must change before any more code is written."

	ctl := enroll.NewUSBController(enroll.USBOptions{SysfsRoot: sysfs})
	before, beforeErr := ctl.USBNets()

	cur, err := d.DHCPSettings(ctx)
	if err != nil {
		return err
	}
	want := enroll.DesiredDHCP(cur, slot)
	rep.Facts = append(rep.Facts,
		fact{Name: "lan_before", Value: cur.DHCPIPAddress.String()},
		fact{Name: "pool_before", Value: cur.DHCPStartIPAddress.String() + "-" + cur.DHCPEndIPAddress.String()},
		fact{Name: "lan_requested", Value: want.DHCPIPAddress.String()},
		fact{Name: "pool_requested", Value: want.DHCPStartIPAddress.String() + "-" + want.DHCPEndIPAddress.String(),
			Note: "the full object is sent; leaving the pool in the old subnet answers 100005"},
	)

	started := time.Now()
	setErr := d.SetDHCPSettings(ctx, want)
	postMS := time.Since(started).Milliseconds()
	switch {
	case setErr == nil:
		rep.Facts = append(rep.Facts, fact{Name: "post_result", Value: "accepted", Note: fmt.Sprintf("%dms", postMS)})
	case errors.Is(setErr, domain.ErrUnsupported):
		rep.Facts = append(rep.Facts, fact{Name: "post_result", Value: "100002 no support"})
		rep.Verdict = "FAIL: this SKU cannot move its LAN subnet. Flat policy routing is impossible for it; the slot needs a namespace. Open an issue against P2 before writing more code."
		return nil
	case enroll.IsProbablySuccess(setErr):
		rep.Facts = append(rep.Facts, fact{Name: "post_result", Value: "no response",
			Note: fmt.Sprintf("%dms; the device stopping mid-request is the expected success signal, not a failure", postMS)})
	default:
		return setErr
	}

	devices, closeDevices, err := buildDevices(cfg)
	if err != nil {
		return err
	}
	defer closeDevices()

	deadline := time.Now().Add(cfg.Carrier.HardDeadline)
	var settled time.Duration
	for time.Now().Before(deadline) {
		nd, derr := devices.ForAddr(ctx, slot.GatewayIP())
		if derr == nil && nd.Reachable(ctx) {
			settled = time.Since(started)
			break
		}
		if serr := domain.SystemClock().Sleep(ctx, cfg.Carrier.PollInterval); serr != nil {
			return serr
		}
	}
	after, afterErr := ctl.USBNets()

	if settled == 0 {
		rep.Facts = append(rep.Facts, fact{Name: "settle", Value: "NEVER", Note: "did not answer at " + slot.GatewayIP().String() + " within " + cfg.Carrier.HardDeadline.String()})
		rep.Verdict = "FAIL: the POST was accepted but the dongle never appeared at the new address. Treat as unsupported."
		return nil
	}
	rep.Facts = append(rep.Facts,
		fact{Name: "settle_ms", Value: strconv.FormatInt(settled.Milliseconds(), 10),
			Note: "budget this into the enrollment re-probe window"},
		usbReenumeratedFact(before, after, beforeErr, afterErr),
	)
	rep.Verdict = fmt.Sprintf("PASS: the LAN subnet moved in %dms. Flat policy routing stands.", settled.Milliseconds())
	return nil
}

func usbReenumeratedFact(before, after []enroll.USBNet, beforeErr, afterErr error) fact {
	if err := errors.Join(beforeErr, afterErr); err != nil {
		return fact{Name: "usb_reenumerated", Value: "UNKNOWN", Note: "could not enumerate usb net devices: " + err.Error()}
	}
	return fact{
		Name:  "usb_reenumerated",
		Value: strconv.FormatBool(!sameNets(before, after)),
		Note:  describeNets(before, after),
	}
}

func sameNets(a, b []enroll.USBNet) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Iface != b[i].Iface || a[i].Device != b[i].Device {
			return false
		}
	}
	return true
}

func describeNets(before, after []enroll.USBNet) string {
	fmtNets := func(n []enroll.USBNet) string {
		var out []string
		for _, v := range n {
			out = append(out, v.Iface+"@"+v.Device)
		}
		return strings.Join(out, ",")
	}
	return "before [" + fmtNets(before) + "] after [" + fmtNets(after) + "]"
}

func probeA3(ctx context.Context, cfg config.Config, addr string, slot domain.Slot, rounds int, rep *probeReport) error {
	d, done, target, err := probeDevice(ctx, cfg, addr, slot)
	if err != nil {
		return err
	}
	defer done()
	rep.Target = target
	rep.Gates = "THE ENTIRE PRODUCT. If no hold produces new addresses there is nothing to sell."
	if rounds < 1 {
		rounds = A3DefaultRounds
	}

	total := rounds * len(A3Ladder())
	fmt.Fprintf(os.Stderr, "a3: %d rotations across %d holds. Rough estimate %s. Do not interrupt.\n",
		total, len(A3Ladder()), estimateA3(rounds, cfg))

	best := 0.0
	for _, hold := range A3Ladder() {
		h := holdResult{HoldSeconds: hold.Seconds()}
		var durations []int64
		seen := map[string]struct{}{}
		for i := 0; i < rounds; i++ {
			old, fresh, dur, rerr := rotateOnce(ctx, d, hold, cfg)
			h.Attempts++
			switch {
			case rerr != nil:
				h.Errors++
				fmt.Fprintf(os.Stderr, "  hold %s round %d/%d: %v\n", hold, i+1, rounds, rerr)
				continue
			case fresh.IsValid() && fresh != old:
				h.Changed++
			default:
				h.Unchanged++
			}
			if fresh.IsValid() {
				seen[fresh.String()] = struct{}{}
			}
			durations = append(durations, dur.Milliseconds())
			fmt.Fprintf(os.Stderr, "  hold %s round %d/%d: %s -> %s in %dms\n",
				hold, i+1, rounds, old, fresh, dur.Milliseconds())
		}
		measured := h.Changed + h.Unchanged
		if measured > 0 {
			h.Rate = float64(h.Changed) / float64(measured)
		}
		h.MedianMS, h.MaxMS = medianMax(durations)
		for a := range seen {
			h.Addresses = append(h.Addresses, a)
		}
		sort.Strings(h.Addresses)
		rep.Ladder = append(rep.Ladder, h)
		if h.Rate > best {
			best = h.Rate
		}
	}

	for _, h := range rep.Ladder {
		rep.Facts = append(rep.Facts, fact{
			Name:  fmt.Sprintf("hold_%gs", h.HoldSeconds),
			Value: fmt.Sprintf("%.0f%% (%d/%d)", h.Rate*100, h.Changed, h.Changed+h.Unchanged),
			Note:  fmt.Sprintf("median %dms, max %dms, %d distinct addresses, %d errors", h.MedianMS, h.MaxMS, len(h.Addresses), h.Errors),
		})
	}
	if best >= A3GateRate {
		rep.Verdict = fmt.Sprintf("PASS: best hold changes the address %.0f%% of the time. Set Carrier.HoldEscalate from the ladder above, cheapest hold that clears the bar first.", best*100)
		return nil
	}
	rep.Verdict = fmt.Sprintf("FAIL: the best hold only reached %.0f%%, the bar is %.0f%%. This carrier and SIM combination cannot be sold as rotating proxies. Stop and re-plan before writing more code.", best*100, A3GateRate*100)
	return nil
}

func estimateA3(rounds int, cfg config.Config) time.Duration {
	var total time.Duration
	for _, hold := range A3Ladder() {
		total += time.Duration(rounds) * (hold + cfg.Carrier.WaitConnect/2)
	}
	return total.Round(time.Minute)
}

func rotateOnce(ctx context.Context, d device.Device, hold time.Duration, cfg config.Config) (netip.Addr, netip.Addr, time.Duration, error) {
	clock := domain.SystemClock()
	old, err := wanIP(ctx, d)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, 0, err
	}
	started := time.Now()

	dataOff := false
	defer func() {
		if !dataOff {
			return
		}
		back, cancel := context.WithTimeout(context.Background(), cfg.Carrier.WaitConnect)
		defer cancel()
		if err := d.DataSwitch(back, true); err != nil {
			fmt.Fprintf(os.Stderr, "probe: mobile data was left off and could not be switched back on: %v\n", err)
		}
	}()

	if err := d.DataSwitch(ctx, false); err != nil {
		return old, netip.Addr{}, 0, err
	}
	dataOff = true

	if err := waitStatus(ctx, d, cfg, clock, func(s device.Status) bool {
		return s.ConnectionStatus == device.ConnDisconnected
	}); err != nil {
		return old, netip.Addr{}, 0, fmt.Errorf("never reached disconnected: %w", err)
	}
	if err := clock.Sleep(ctx, hold); err != nil {
		return old, netip.Addr{}, 0, err
	}
	if err := d.DataSwitch(ctx, true); err != nil {
		return old, netip.Addr{}, 0, err
	}
	dataOff = false
	if err := waitStatus(ctx, d, cfg, clock, func(s device.Status) bool {
		return s.ConnectionStatus.Connected()
	}); err != nil {
		return old, netip.Addr{}, time.Since(started), fmt.Errorf("never reconnected: %w", err)
	}
	fresh, err := wanIP(ctx, d)
	return old, fresh, time.Since(started), err
}

func waitStatus(ctx context.Context, d device.Device, cfg config.Config, clock domain.Clock, ok func(device.Status) bool) error {
	deadline := time.Now().Add(cfg.Carrier.WaitConnect)
	for time.Now().Before(deadline) {
		s, err := d.Status(ctx)
		if err == nil && ok(s) {
			return nil
		}
		if err := clock.Sleep(ctx, cfg.Carrier.PollInterval); err != nil {
			return err
		}
	}
	return context.DeadlineExceeded
}

func wanIP(ctx context.Context, d device.Device) (netip.Addr, error) {
	s, err := d.Status(ctx)
	if err == nil && s.WanIP.IsValid() {
		return s.WanIP, nil
	}
	info, ierr := d.Information(ctx)
	if ierr != nil {
		if err != nil {
			return netip.Addr{}, err
		}
		return netip.Addr{}, ierr
	}
	return info.WanIPAddress, nil
}

func medianMax(v []int64) (int64, int64) {
	if len(v) == 0 {
		return 0, 0
	}
	s := append([]int64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2], s[len(s)-1]
}

func renderMarkdown(rep probeReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n### %s — experiment %s\n\n", rep.StartedAt.Format("2006-01-02 15:04 MST"), strings.ToUpper(rep.Experiment))
	fmt.Fprintf(&b, "- host `%s`, kernel `%s`", rep.Host, rep.Kernel)
	if rep.Target != "" {
		fmt.Fprintf(&b, ", target `%s`", rep.Target)
	}
	fmt.Fprintf(&b, ", took %s\n", (time.Duration(rep.DurationMS) * time.Millisecond).Round(time.Second))
	fmt.Fprintf(&b, "- gates: %s\n\n", rep.Gates)

	if len(rep.Facts) > 0 {
		fmt.Fprintf(&b, "| measurement | value | note |\n|---|---|---|\n")
		for _, f := range rep.Facts {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", f.Name, f.Value, f.Note)
		}
		fmt.Fprintln(&b)
	}
	if len(rep.Ladder) > 0 {
		fmt.Fprintf(&b, "| hold | attempts | ip changed | unchanged | errors | rate | median | max |\n|---|---|---|---|---|---|---|---|\n")
		for _, h := range rep.Ladder {
			fmt.Fprintf(&b, "| %gs | %d | %d | %d | %d | %.0f%% | %dms | %dms |\n",
				h.HoldSeconds, h.Attempts, h.Changed, h.Unchanged, h.Errors, h.Rate*100, h.MedianMS, h.MaxMS)
		}
		fmt.Fprintln(&b)
	}
	if len(rep.Samples) > 0 {
		for _, s := range rep.Samples {
			raw, _ := json.Marshal(s)
			fmt.Fprintf(&b, "- `%s`\n", raw)
		}
		fmt.Fprintln(&b)
	}
	fmt.Fprintf(&b, "**%s**\n", rep.Verdict)
	return b.String()
}

func appendMarkdown(path string, rep probeReport) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(renderMarkdown(rep))
	return err
}

func writeJSONFile(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
