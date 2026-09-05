package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/n4darae/huawei-API/src/internal/netcfg"
)

func encodeAttr(kind uint16, data []byte) []byte {
	length := sizeofNlAttr + len(data)
	buf := make([]byte, (length+3)&^3)
	binary.NativeEndian.PutUint16(buf[0:2], uint16(length))
	binary.NativeEndian.PutUint16(buf[2:4], kind)
	copy(buf[sizeofNlAttr:], data)
	return buf
}

func TestParseAttrsHandlesPaddingAndTrailer(t *testing.T) {
	var b []byte
	b = append(b, encodeAttr(iflaIfname, []byte("dg01\x00"))...)
	b = append(b, encodeAttr(iflaMTU, []byte{0xdc, 0x05, 0, 0})...)
	attrs, err := parseAttrs(b)
	if err != nil {
		t.Fatalf("parseAttrs: %v", err)
	}
	if len(attrs) != 2 {
		t.Fatalf("want 2 attributes, got %d", len(attrs))
	}
	if got := attrString(attrs[0]); got != "dg01" {
		t.Fatalf("interface name %q", got)
	}
	if v, ok := attrU32(attrs[1]); !ok || v != 1500 {
		t.Fatalf("mtu %d ok=%v", v, ok)
	}
}

func TestParseAttrsRejectsATruncatedHeader(t *testing.T) {
	b := encodeAttr(iflaIfname, []byte("dg01\x00"))
	binary.NativeEndian.PutUint16(b[0:2], 9999)
	if _, err := parseAttrs(b); err == nil {
		t.Fatal("an over-long attribute must be rejected")
	}
}

func TestAttrAddr(t *testing.T) {
	v4, ok := attrAddr(attr{Data: []byte{192, 168, 101, 100}})
	if !ok || v4 != netip.MustParseAddr("192.168.101.100") {
		t.Fatalf("v4 decode: %v ok=%v", v4, ok)
	}
	if _, ok := attrAddr(attr{Data: []byte{1, 2, 3}}); ok {
		t.Fatal("a malformed address must be rejected")
	}
}

func TestAttrMAC(t *testing.T) {
	got := attrMAC(attr{Data: []byte{0x0c, 0x5b, 0x8f, 0x27, 0x9a, 0x01}})
	if got != "0c:5b:8f:27:9a:01" {
		t.Fatalf("mac %q", got)
	}
	if attrMAC(attr{Data: []byte{1, 2}}) != "" {
		t.Fatal("a short mac must decode to empty")
	}
}

func TestParseRouteGet(t *testing.T) {
	res := parseRouteGet("1.1.1.1 from 192.168.101.100 via 192.168.101.1 dev dg01 table 1001 src 192.168.101.100 uid 6101 \n    cache \n")
	if res.Dev != "dg01" {
		t.Fatalf("dev %q", res.Dev)
	}
	if res.Table != 1001 {
		t.Fatalf("table %d", res.Table)
	}
	if res.Src != netip.MustParseAddr("192.168.101.100") {
		t.Fatalf("src %v", res.Src)
	}
}

func TestParseRouteGetWithoutTable(t *testing.T) {
	res := parseRouteGet("1.1.1.1 via 10.90.0.2 dev pub0 src 10.90.0.1 uid 6101 \n    cache \n")
	if res.Dev != "pub0" || res.Table != 0 {
		t.Fatalf("dev %q table %d", res.Dev, res.Table)
	}
}

func TestDuplicateAddrsIgnoresLinkLocalAndLoopback(t *testing.T) {
	links := map[string]netcfg.LinkState{
		"lo":   {Name: "lo", Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		"dg01": {Name: "dg01", Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.101.100/24"), netip.MustParsePrefix("fe80::1/64")}},
		"dg02": {Name: "dg02", Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.102.100/24"), netip.MustParsePrefix("fe80::1/64")}},
	}
	if got := DuplicateAddrs(links); len(got) != 0 {
		t.Fatalf("link-local and loopback must not count as duplicates, got %v", got)
	}
	links["dg02"] = netcfg.LinkState{Name: "dg02", Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.101.100/24")}}
	got := DuplicateAddrs(links)
	if len(got) != 1 || got[0].Addr() != netip.MustParseAddr("192.168.101.100") {
		t.Fatalf("a genuinely duplicated address must be reported, got %v", got)
	}
}

func TestFormatRule(t *testing.T) {
	r := netcfg.RuleState{
		Priority:   1501,
		Table:      1001,
		UIDRangeLo: 6101,
		UIDRangeHi: 6101,
		Action:     "lookup",
	}
	if got := formatRule(r); got != "1501: from all uidrange 6101-6101 lookup 1001" {
		t.Fatalf("formatRule %q", got)
	}
	r = netcfg.RuleState{
		Priority:   900,
		Table:      rtTableMain,
		Src:        netip.MustParsePrefix("139.99.68.39/32"),
		IifName:    "lo",
		Action:     "lookup",
		UIDRangeLo: -1,
		UIDRangeHi: -1,
	}
	if got := formatRule(r); got != "900: from 139.99.68.39/32 iif lo lookup main" {
		t.Fatalf("formatRule %q", got)
	}
}

func TestLinkAndRuleDumpsWorkAgainstTheRunningKernel(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rtnetlink dumps need a linux kernel")
	}
	o := NewObserver(nil)
	ctx := context.Background()
	links, err := o.Links(ctx)
	if err != nil {
		t.Fatalf("Links: %v", err)
	}
	lo, ok := links["lo"]
	if !ok {
		t.Fatal("every namespace has a loopback interface")
	}
	if !lo.Up() {
		t.Fatalf("loopback operstate %q must count as up", lo.OperState)
	}
	rules, err := o.Rules(ctx)
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.Priority == 32766 && r.Table == rtTableMain {
			found = true
		}
	}
	if !found {
		t.Fatalf("the kernel default rule 32766 -> main is missing from %v", rules)
	}
	routes, err := o.Routes(ctx)
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("route dump returned nothing")
	}
}

func TestDumpsRefuseACancelledContextInsteadOfBlocking(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rtnetlink dumps need a linux kernel")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	o := NewObserver(nil)
	for name, call := range map[string]func() error{
		"Links":  func() error { _, err := o.Links(ctx); return err },
		"Rules":  func() error { _, err := o.Rules(ctx); return err },
		"Routes": func() error { _, err := o.Routes(ctx); return err },
	} {
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("%s on a cancelled context returned %v, want context.Canceled", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s ignored the cancelled context and blocked", name)
		}
	}
}

func TestSubscribeExitsOnContextCancelWithoutCallingCancel(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rtnetlink subscribe needs a linux kernel")
	}
	ctx, cancel := context.WithCancel(context.Background())
	o := NewObserver(nil)
	ch, _, err := o.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel must be closed after ctx cancel, not deliver an event")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader goroutine did not exit promptly after ctx cancel")
	}
}

func TestOperStateUnknownCountsAsUp(t *testing.T) {
	for _, s := range []string{netcfg.OperStateUp, netcfg.OperStateUnknown} {
		if !(netcfg.LinkState{OperState: s}).Up() {
			t.Fatalf("hilink cdc_ether devices report %q forever and must count as up", s)
		}
	}
	if (netcfg.LinkState{OperState: netcfg.OperStateDown}).Up() {
		t.Fatal("down must not count as up")
	}
}
