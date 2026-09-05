package main

import (
	"context"
	"strconv"

	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/metrics"
	"github.com/n4darae/huawei-API/src/internal/proxysup"
	"github.com/n4darae/huawei-API/src/internal/reconcile"
	"github.com/n4darae/huawei-API/src/internal/store"
)

type metric = metrics.Metric

type observer interface {
	Snapshot() reconcile.ObservedState
}

type metricsCollector struct {
	nodeID   string
	version  string
	repos    store.Repos
	observer observer
}

func (c *metricsCollector) Metrics(ctx context.Context) []metric {
	out := []metric{{
		Name:    "dongled_build_info",
		Help:    "1 with the running version and node id as labels",
		Samples: []metrics.Sample{{Labels: map[string]string{"version": c.version, "node_id": c.nodeID}, Value: 1}},
	}}
	out = append(out, c.storeMetrics(ctx)...)
	out = append(out, c.snapshotMetrics()...)
	return out
}

func (c *metricsCollector) storeMetrics(ctx context.Context) []metric {
	if c.repos == nil {
		return nil
	}
	failed := 0.0
	var out []metric

	if slots, err := c.repos.Slots().List(ctx, c.nodeID); err == nil {
		occupied := 0.0
		for _, s := range slots {
			if s.Occupied() {
				occupied++
			}
		}
		out = append(out,
			metric{
				Name:    "dongled_slots_total",
				Help:    "slots enrolled on this node",
				Samples: []metrics.Sample{{Value: float64(len(slots))}},
			},
			metric{
				Name:    "dongled_slots_occupied",
				Help:    "slots with a dongle attached",
				Samples: []metrics.Sample{{Value: occupied}},
			},
		)
	} else {
		failed = 1
	}

	if proxies, err := c.repos.Proxies().List(ctx, store.ProxyFilter{}); err == nil {
		enabled, suspended := 0.0, 0.0
		for _, p := range proxies {
			if p.Enabled {
				enabled++
			}
			if p.Suspended {
				suspended++
			}
		}
		out = append(out,
			metric{
				Name:    "dongled_proxies_total",
				Help:    "proxies known to this node",
				Samples: []metrics.Sample{{Value: float64(len(proxies))}},
			},
			metric{
				Name:    "dongled_proxies_enabled",
				Help:    "proxies currently enabled",
				Samples: []metrics.Sample{{Value: enabled}},
			},
			metric{
				Name:    "dongled_proxies_suspended",
				Help:    "proxies currently suspended",
				Samples: []metrics.Sample{{Value: suspended}},
			},
		)
	} else {
		failed = 1
	}

	if ops, err := c.repos.Operations().ListActive(ctx); err == nil {
		out = append(out, metric{
			Name:    "dongled_operations_active",
			Help:    "operations still in flight",
			Samples: []metrics.Sample{{Value: float64(len(ops))}},
		})
	} else {
		failed = 1
	}

	return append(out, metric{
		Name:    "dongled_scrape_failed",
		Help:    "1 when at least one metric could not be read from the database",
		Samples: []metrics.Sample{{Value: failed}},
	})
}

func (c *metricsCollector) snapshotMetrics() []metric {
	if c.observer == nil {
		return nil
	}
	st := c.observer.Snapshot()

	lastSweep := 0.0
	if !st.LastSweepAt.IsZero() {
		lastSweep = float64(st.LastSweepAt.UnixNano()) / 1e9
	}

	out := []metric{
		{
			Name:    "dongled_reconcile_sweeps_total",
			Help:    "reconcile sweeps completed since start",
			Kind:    metrics.Counter,
			Samples: []metrics.Sample{{Value: float64(st.SweepsCompleted)}},
		},
		{
			Name:    "dongled_reconcile_last_sweep_timestamp_seconds",
			Help:    "unix time of the last completed reconcile sweep, 0 when none has finished",
			Samples: []metrics.Sample{{Value: lastSweep}},
		},
		{
			Name:    "dongled_nft_table_present",
			Help:    "1 when the nftables table is installed",
			Samples: []metrics.Sample{{Value: metrics.Bool(st.NftTablePresent)}},
		},
		{
			Name:    "dongled_ip_forward",
			Help:    "1 when net.ipv4.ip_forward is on",
			Samples: []metrics.Sample{{Value: metrics.Bool(st.Net.IPForward)}},
		},
		{
			Name:    "dongled_route_table_names_ok",
			Help:    "1 when rt_tables carries every slot table name",
			Samples: []metrics.Sample{{Value: metrics.Bool(st.Net.RouteTableNamesOK)}},
		},
		{
			Name:    "dongled_duplicate_addresses",
			Help:    "addresses observed on more than one link",
			Samples: []metrics.Sample{{Value: float64(len(st.Net.DuplicateAddrs))}},
		},
		{
			Name:    "dongled_foreign_rules_below_ceiling",
			Help:    "policy rules from other software below the reserved priority ceiling",
			Samples: []metrics.Sample{{Value: float64(len(st.Net.ForeignRuleBelowCeil))}},
		},
	}

	if fenced := fencedSamples(st.Fenced); len(fenced) > 0 {
		out = append(out, metric{
			Name:    "dongled_slot_fenced",
			Help:    "1 when the slot interface is fenced against egress",
			Samples: fenced,
		})
	}
	out = append(out, proxyMetrics(st.ProxyStatus)...)
	return append(out, deviceMetrics(st.Devices)...)
}

func fencedSamples(fenced map[string]bool) []metrics.Sample {
	out := make([]metrics.Sample, 0, len(fenced))
	for iface, on := range fenced {
		out = append(out, metrics.Sample{Labels: map[string]string{"iface": iface}, Value: metrics.Bool(on)})
	}
	return out
}

func proxyMetrics(status map[domain.Slot]proxysup.Status) []metric {
	if len(status) == 0 {
		return nil
	}
	running := make([]metrics.Sample, 0, len(status))
	healthy := make([]metrics.Sample, 0, len(status))
	for slot, st := range status {
		l := slotLabels(slot)
		running = append(running, metrics.Sample{Labels: l, Value: metrics.Bool(st.Running)})
		healthy = append(healthy, metrics.Sample{Labels: l, Value: metrics.Bool(st.Healthy())})
	}
	return []metric{
		{
			Name:    "dongled_proxy_running",
			Help:    "1 when the 3proxy unit for the slot is running",
			Samples: running,
		},
		{
			Name:    "dongled_proxy_healthy",
			Help:    "1 when both listeners are bound and the probe succeeded",
			Samples: healthy,
		},
	}
}

func deviceMetrics(devices map[domain.Slot]reconcile.DeviceObservation) []metric {
	if len(devices) == 0 {
		return nil
	}
	reachable := make([]metrics.Sample, 0, len(devices))
	conn := make([]metrics.Sample, 0, len(devices))
	sim := make([]metrics.Sample, 0, len(devices))
	bars := make([]metrics.Sample, 0, len(devices))
	rssi := make([]metrics.Sample, 0, len(devices))
	rx := make([]metrics.Sample, 0, len(devices))
	tx := make([]metrics.Sample, 0, len(devices))

	for slot, d := range devices {
		l := slotLabels(slot)
		reachable = append(reachable, metrics.Sample{Labels: l, Value: metrics.Bool(d.Reachable)})
		conn = append(conn, metrics.Sample{Labels: l, Value: float64(d.Conn)})
		sim = append(sim, metrics.Sample{Labels: l, Value: float64(d.Sim)})
		bars = append(bars, metrics.Sample{Labels: l, Value: float64(d.Signal.Bars)})
		rssi = append(rssi, metrics.Sample{Labels: l, Value: float64(d.Signal.RSSI)})
		rx = append(rx, metrics.Sample{Labels: l, Value: float64(d.Traffic.TotalDownload)})
		tx = append(tx, metrics.Sample{Labels: l, Value: float64(d.Traffic.TotalUpload)})
	}

	return []metric{
		{
			Name:    "dongled_device_reachable",
			Help:    "1 when the dongle answered the last poll",
			Samples: reachable,
		},
		{
			Name:    "dongled_device_connection_status",
			Help:    "HiLink connection status code, 901 is connected",
			Samples: conn,
		},
		{
			Name:    "dongled_device_sim_state",
			Help:    "HiLink SIM state code, 257 is ready",
			Samples: sim,
		},
		{
			Name:    "dongled_device_signal_bars",
			Help:    "signal bars reported by the dongle",
			Samples: bars,
		},
		{
			Name:    "dongled_device_signal_rssi_dbm",
			Help:    "signal RSSI in dBm",
			Samples: rssi,
		},
		{
			Name:    "dongled_device_rx_bytes_total",
			Help:    "bytes downloaded over the life of the SIM counter",
			Kind:    metrics.Counter,
			Samples: rx,
		},
		{
			Name:    "dongled_device_tx_bytes_total",
			Help:    "bytes uploaded over the life of the SIM counter",
			Kind:    metrics.Counter,
			Samples: tx,
		},
	}
}

func slotLabels(slot domain.Slot) map[string]string {
	return map[string]string{
		"slot":  strconv.Itoa(slot.Int()),
		"iface": slot.IfaceName(),
	}
}
