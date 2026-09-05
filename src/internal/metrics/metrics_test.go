package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEncodeWritesHelpTypeAndSortedLabels(t *testing.T) {
	var b strings.Builder
	err := Encode(&b, []Metric{{
		Name: "dongled_slot_fenced",
		Help: "1 when the slot interface is fenced",
		Kind: Gauge,
		Samples: []Sample{
			{Labels: map[string]string{"slot": "1", "iface": "dg01"}, Value: 1},
			{Labels: map[string]string{"slot": "2", "iface": "dg02"}, Value: 0},
		},
	}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := "# HELP dongled_slot_fenced 1 when the slot interface is fenced\n" +
		"# TYPE dongled_slot_fenced gauge\n" +
		"dongled_slot_fenced{iface=\"dg01\",slot=\"1\"} 1\n" +
		"dongled_slot_fenced{iface=\"dg02\",slot=\"2\"} 0\n"
	if got := b.String(); got != want {
		t.Fatalf("encoded output is\n%q\nwant\n%q", got, want)
	}
}

func TestEncodeSkipsMetricsWithoutSamples(t *testing.T) {
	var b strings.Builder
	if err := Encode(&b, []Metric{{Name: "dongled_nothing", Help: "h"}}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if b.String() != "" {
		t.Fatalf("a metric with no samples produced %q, want nothing", b.String())
	}
}

func TestEncodeEscapesLabelValuesAndHelp(t *testing.T) {
	var b strings.Builder
	if err := Encode(&b, []Metric{{
		Name:    "dongled_last_error",
		Help:    "line one\nline two",
		Samples: []Sample{{Labels: map[string]string{"msg": `he said "no"\ever`}, Value: 1}},
	}}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got := b.String()
	if !strings.Contains(got, `# HELP dongled_last_error line one\nline two`) {
		t.Fatalf("help was not escaped in %q", got)
	}
	if !strings.Contains(got, `msg="he said \"no\"\\ever"`) {
		t.Fatalf("label value was not escaped in %q", got)
	}
	if strings.Count(got, "\n") != 3 {
		t.Fatalf("escaping leaked a raw newline into %q", got)
	}
}

func TestEncodeDefaultsTheTypeToGauge(t *testing.T) {
	var b strings.Builder
	if err := Encode(&b, []Metric{{Name: "dongled_up", Samples: []Sample{{Value: 1}}}}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !strings.Contains(b.String(), "# TYPE dongled_up gauge\n") {
		t.Fatalf("missing default type in %q", b.String())
	}
	if strings.Contains(b.String(), "# HELP") {
		t.Fatalf("an empty help string still emitted a HELP line: %q", b.String())
	}
}

func TestEncodeWritesIntegersWithoutAnExponent(t *testing.T) {
	var b strings.Builder
	if err := Encode(&b, []Metric{{
		Name:    "dongled_bytes_total",
		Kind:    Counter,
		Samples: []Sample{{Value: 1234567890}},
	}}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !strings.Contains(b.String(), "dongled_bytes_total 1234567890\n") {
		t.Fatalf("large integer was not written verbatim: %q", b.String())
	}
}

func TestEncodeWritesFractionalValuesWithoutAnExponent(t *testing.T) {
	var b strings.Builder
	if err := Encode(&b, []Metric{{
		Name:    "dongled_last_sweep_timestamp_seconds",
		Samples: []Sample{{Value: 1788540658.941547}},
	}}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !strings.Contains(b.String(), "dongled_last_sweep_timestamp_seconds 1788540658.941547\n") {
		t.Fatalf("fractional value was written in exponent form: %q", b.String())
	}
}

func TestHandlerServesEveryNonNilSource(t *testing.T) {
	a := SourceFunc(func(context.Context) []Metric {
		return []Metric{{Name: "a_metric", Samples: []Sample{{Value: 1}}}}
	})
	b := SourceFunc(func(context.Context) []Metric {
		return []Metric{{Name: "b_metric", Samples: []Sample{{Value: 2}}}}
	})

	rec := httptest.NewRecorder()
	Handler(a, nil, b).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status is %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != ContentType {
		t.Fatalf("content type is %q, want %q", ct, ContentType)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "a_metric 1\n") || !strings.Contains(body, "b_metric 2\n") {
		t.Fatalf("body is missing a source: %q", body)
	}
}

func TestHandlerRefusesAWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics returned %d, want 405", rec.Code)
	}
	if rec.Header().Get("Allow") == "" {
		t.Fatal("a 405 without an Allow header")
	}
}

func TestHandlerAnswersHeadWithoutABody(t *testing.T) {
	src := SourceFunc(func(context.Context) []Metric {
		return []Metric{{Name: "a_metric", Samples: []Sample{{Value: 1}}}}
	})
	rec := httptest.NewRecorder()
	Handler(src).ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status is %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD returned a body: %q", rec.Body.String())
	}
}

func TestBoolMapsToOneAndZero(t *testing.T) {
	if Bool(true) != 1 || Bool(false) != 0 {
		t.Fatalf("Bool maps to %v/%v, want 1/0", Bool(true), Bool(false))
	}
}
