package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/n4darae/huawei-API/src/internal/config"
	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/eventbus"
	"github.com/n4darae/huawei-API/src/internal/httpapi"
	"github.com/n4darae/huawei-API/src/internal/metrics"
)

type App struct {
	Cfg     config.Config
	Clock   domain.Clock
	Bus     eventbus.Bus
	Router  http.Handler
	Panel   *http.Server
	Metrics *http.Server

	sources []metrics.Source
	closers []func(context.Context) error
}

func (a *App) AddMetricsSource(s metrics.Source) {
	if s != nil {
		a.sources = append(a.sources, s)
	}
}

type ModuleFactory func(ctx context.Context, app *App) (httpapi.Mounter, error)

var moduleFactories []ModuleFactory

func RegisterModule(f ModuleFactory) { moduleFactories = append(moduleFactories, f) }

func (a *App) OnClose(f func(context.Context) error) { a.closers = append(a.closers, f) }

func Wire(ctx context.Context, cfg config.Config) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	bus := eventbus.NewMemBus(eventbus.DefaultSubscriberBuffer)

	app := &App{
		Cfg:   cfg,
		Clock: domain.SystemClock(),
		Bus:   bus,
	}
	app.OnClose(func(context.Context) error {
		bus.Close()
		return nil
	})

	mods := make([]httpapi.Mounter, 0, len(moduleFactories))
	for _, f := range moduleFactories {
		m, err := f(ctx, app)
		if err != nil {
			return nil, err
		}
		if m != nil {
			mods = append(mods, m)
		}
	}

	app.Router = httpapi.NewRouter(app.health, mods...)
	app.Panel = &http.Server{
		Addr:              cfg.PanelAddr,
		Handler:           app.Router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", metrics.Handler(app.sources...))
	app.Metrics = &http.Server{
		Addr:              cfg.MetricsAddr,
		Handler:           metricsMux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return app, nil
}

func (a *App) health(*http.Request) (int, any) {
	return http.StatusOK, map[string]any{
		"status":     "ok",
		"product":    config.Product,
		"node_id":    a.Cfg.NodeID,
		"invariants": []any{},
	}
}

func (a *App) Run(ctx context.Context) error {
	errs := make(chan error, 2)
	go func() { errs <- serve(a.Panel) }()
	go func() { errs <- serve(a.Metrics) }()

	select {
	case <-ctx.Done():
	case err := <-errs:
		if err != nil {
			return err
		}
	}
	return a.Close(context.WithoutCancel(ctx))
}

func serve(s *http.Server) error {
	err := s.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *App) Close(ctx context.Context) error {
	shutdown, cancel := context.WithTimeout(ctx, a.Cfg.ShutdownGrace)
	defer cancel()

	var first error
	for _, s := range []*http.Server{a.Panel, a.Metrics} {
		if s == nil {
			continue
		}
		if err := s.Shutdown(shutdown); err != nil && first == nil {
			first = err
		}
	}
	for i := len(a.closers) - 1; i >= 0; i-- {
		if err := a.closers[i](shutdown); err != nil && first == nil {
			first = err
		}
	}
	return first
}
