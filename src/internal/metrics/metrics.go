package metrics

import (
	"context"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const ContentType = "text/plain; version=0.0.4; charset=utf-8"

type Kind string

const (
	Gauge   Kind = "gauge"
	Counter Kind = "counter"
)

type Sample struct {
	Labels map[string]string
	Value  float64
}

type Metric struct {
	Name    string
	Help    string
	Kind    Kind
	Samples []Sample
}

type Source interface {
	Metrics(ctx context.Context) []Metric
}

type SourceFunc func(ctx context.Context) []Metric

func (f SourceFunc) Metrics(ctx context.Context) []Metric { return f(ctx) }

func Bool(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func Handler(sources ...Source) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var all []Metric
		for _, s := range sources {
			if s == nil {
				continue
			}
			all = append(all, s.Metrics(r.Context())...)
		}
		w.Header().Set("Content-Type", ContentType)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = Encode(w, all)
	})
}

func Encode(w io.Writer, ms []Metric) error {
	var b strings.Builder
	for _, m := range ms {
		if m.Name == "" || len(m.Samples) == 0 {
			continue
		}
		if m.Help != "" {
			b.WriteString("# HELP ")
			b.WriteString(m.Name)
			b.WriteByte(' ')
			b.WriteString(escapeHelp(m.Help))
			b.WriteByte('\n')
		}
		kind := m.Kind
		if kind == "" {
			kind = Gauge
		}
		b.WriteString("# TYPE ")
		b.WriteString(m.Name)
		b.WriteByte(' ')
		b.WriteString(string(kind))
		b.WriteByte('\n')

		for _, s := range m.Samples {
			b.WriteString(m.Name)
			writeLabels(&b, s.Labels)
			b.WriteByte(' ')
			b.WriteString(formatValue(s.Value))
			b.WriteByte('\n')
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeLabels(b *strings.Builder, labels map[string]string) {
	if len(labels) == 0 {
		return
	}
	names := make([]string, 0, len(labels))
	for k := range labels {
		names = append(names, k)
	}
	sort.Strings(names)

	b.WriteByte('{')
	for i, k := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(escapeLabel(labels[k]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
}

func formatValue(v float64) string {
	if v == math.Trunc(v) && !math.IsInf(v, 0) && math.Abs(v) < 1<<53 {
		return strconv.FormatInt(int64(v), 10)
	}
	if math.IsInf(v, 0) || math.IsNaN(v) {
		return strconv.FormatFloat(v, 'g', -1, 64)
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func escapeHelp(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "\n", `\n`)
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return strings.ReplaceAll(s, "\n", `\n`)
}
