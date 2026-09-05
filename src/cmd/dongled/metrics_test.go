package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/n4darae/huawei-API/src/internal/device"
	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/metrics"
	"github.com/n4darae/huawei-API/src/internal/netcfg"
	"github.com/n4darae/huawei-API/src/internal/proxysup"
	"github.com/n4darae/huawei-API/src/internal/reconcile"
)

type stubObserver struct{ st reconcile.ObservedState }

func (o stubObserver) Snapshot() reconcile.ObservedState { return o.st }

func renderCollector(t *testing.T, c *metricsCollector) string {
	t.Helper()
	var b strings.Builder
	if err := metrics.Encode(&b, c.Metrics(context.Background())); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return b.String()
}

func TestCollectorReportsBuildInfoWithoutAnyBackend(t *testing.T) {
	got := renderCollector(t, &metricsCollector{nodeID: "n1", version: "1.2.3"})
	if !strings.Contains(got, `dongled_build_info{node_id="n1",version="1.2.3"} 1`) {
		t.Fatalf("build info missing from\n%s", got)
	}
}

func TestCollectorRendersTheReconcileSnapshot(t *testing.T) {
	sweep := time.Unix(1788539830, 0)
	c := &metricsCollector{
		nodeID:  "n1",
		version: "dev",
		observer: stubObserver{st: reconcile.ObservedState{
			NftTablePresent: true,
			SweepsCompleted: 42,
			LastSweepAt:     sweep,
			Net: netcfg.Observation{
				IPForward:         true,
				RouteTableNamesOK: false,
			},
			Fenced: map[string]bool{"dg01": true},
			ProxyStatus: map[domain.Slot]proxysup.Status{
				1: {Running: true, SocksBound: true, HTTPBound: true, ProbeOK: true},
			},
			Devices: map[domain.Slot]reconcile.DeviceObservation{
				1: {
					Reachable: true,
					Conn:      device.ConnConnected,
					Sim:       device.SimStateReady,
					Signal:    device.Signal{Bars: 4, RSSI: -61},
					Traffic:   device.Traffic{TotalDownload: 9000000000, TotalUpload: 12345},
				},
			},
		}},
	}

	got := renderCollector(t, c)
	for _, want := range []string{
		"dongled_reconcile_sweeps_total 42",
		"# TYPE dongled_reconcile_sweeps_total counter",
		"dongled_reconcile_last_sweep_timestamp_seconds 1788539830",
		"dongled_nft_table_present 1",
		"dongled_ip_forward 1",
		"dongled_route_table_names_ok 0",
		`dongled_slot_fenced{iface="dg01"} 1`,
		`dongled_proxy_running{iface="dg01",slot="1"} 1`,
		`dongled_proxy_healthy{iface="dg01",slot="1"} 1`,
		`dongled_device_reachable{iface="dg01",slot="1"} 1`,
		`dongled_device_connection_status{iface="dg01",slot="1"} 901`,
		`dongled_device_sim_state{iface="dg01",slot="1"} 257`,
		`dongled_device_signal_bars{iface="dg01",slot="1"} 4`,
		`dongled_device_signal_rssi_dbm{iface="dg01",slot="1"} -61`,
		`dongled_device_rx_bytes_total{iface="dg01",slot="1"} 9000000000`,
		`dongled_device_tx_bytes_total{iface="dg01",slot="1"} 12345`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestCollectorReportsAnUnhealthyProxyThatIsStillRunning(t *testing.T) {
	c := &metricsCollector{
		observer: stubObserver{st: reconcile.ObservedState{
			ProxyStatus: map[domain.Slot]proxysup.Status{
				2: {Running: true, SocksBound: true, HTTPBound: false, ProbeOK: true},
			},
		}},
	}
	got := renderCollector(t, c)
	if !strings.Contains(got, `dongled_proxy_running{iface="dg02",slot="2"} 1`) {
		t.Fatalf("running gauge missing from\n%s", got)
	}
	if !strings.Contains(got, `dongled_proxy_healthy{iface="dg02",slot="2"} 0`) {
		t.Fatalf("a proxy with an unbound listener was reported healthy in\n%s", got)
	}
}

func TestCollectorLeavesTheSweepTimestampAtZeroBeforeTheFirstSweep(t *testing.T) {
	c := &metricsCollector{observer: stubObserver{st: reconcile.ObservedState{}}}
	if got := renderCollector(t, c); !strings.Contains(got, "dongled_reconcile_last_sweep_timestamp_seconds 0") {
		t.Fatalf("expected a zero sweep timestamp in\n%s", got)
	}
}
