package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/n4darae/huawei-API/src/internal/auth"
	"github.com/n4darae/huawei-API/src/internal/config"
	"github.com/n4darae/huawei-API/src/internal/devops"
	"github.com/n4darae/huawei-API/src/internal/httpapi"
	"github.com/n4darae/huawei-API/src/internal/logging"
	"github.com/n4darae/huawei-API/src/internal/proxysup"
	"github.com/n4darae/huawei-API/src/internal/ratelimit"
	"github.com/n4darae/huawei-API/src/internal/reconcile"
	"github.com/n4darae/huawei-API/src/internal/rotate"
	"github.com/n4darae/huawei-API/src/internal/store"
	"github.com/n4darae/huawei-API/src/internal/webui"
)

func init() {
	RegisterModule(buildPanel)
}

func buildPanel(ctx context.Context, app *App) (httpapi.Mounter, error) {
	cfg := app.Cfg
	log := logging.New(os.Stderr, cfg.LogLevel)

	db, err := openPanelStore(ctx, cfg)
	if err != nil {
		return nil, err
	}
	app.OnClose(func(context.Context) error { return db.Close() })

	if err := auth.EnsureSchema(ctx, db.DB()); err != nil {
		return nil, err
	}

	secureCookies, err := resolveSecureCookies(os.LookupEnv)
	if err != nil {
		return nil, err
	}
	if !secureCookies {
		log.Warn("insecure session cookies allowed via DONGLED_ALLOW_INSECURE_COOKIES=1, do not use in production")
	}
	sessions := auth.NewSessions(db.DB(), cfg.SessionTTL, app.Clock.Now)
	keys := auth.NewKeys(db.DB(), app.Clock.Now)
	lockout := auth.NewLockout(db.DB(), auth.DefaultLockoutPolicy(), app.Clock.Now)

	if err := seedDevAdmin(ctx, cfg, sessions); err != nil {
		return nil, err
	}
	if !webui.Built() {
		log.Warn("the web panel bundle is not built, / serves a placeholder; run make web-install && make web, then rebuild")
	}
	if ok, err := sessions.HasUsers(ctx); err == nil && !ok {
		log.Warn("no panel account exists yet, nobody can sign in; create one with " + config.Product + " passwd")
	}

	devices, closeDevices, err := buildDevicesFor(cfg, false)
	if err != nil {
		return nil, err
	}
	app.OnClose(func(context.Context) error { closeDevices(); return nil })

	firewall, err := buildFirewall(ctx, cfg)
	if err != nil {
		return nil, err
	}
	network, err := buildNetcfg(cfg)
	if err != nil {
		return nil, err
	}
	supervisor, err := panelSupervisor(cfg)
	if err != nil {
		return nil, err
	}

	ops, err := devops.New(devops.Deps{
		Repos:  db,
		Dev:    devices,
		Net:    network,
		Bus:    app.Bus,
		Clock:  app.Clock,
		NodeID: cfg.NodeID,
	})
	if err != nil {
		return nil, err
	}
	app.OnClose(func(c context.Context) error { return ops.Shutdown(c) })

	prober, err := rotate.NewProber(rotate.ProberOptions{})
	if err != nil {
		return nil, err
	}

	rotator, err := rotate.New(rotate.Deps{
		Repos:  db,
		Dev:    devices,
		FW:     firewall,
		Probe:  prober,
		Reboot: ops,
		Bus:    app.Bus,
		Clock:  app.Clock,
		Policy: policyFromConfig(cfg),
		NodeID: cfg.NodeID,
	})
	if err != nil {
		return nil, err
	}
	app.OnClose(func(c context.Context) error { return rotator.Shutdown(c) })

	engine, err := reconcile.NewEngine(reconcile.Deps{
		NodeID:            cfg.NodeID,
		Repos:             db,
		Net:               network,
		FW:                firewall,
		Proxy:             supervisor,
		Dev:               devices,
		Bus:               app.Bus,
		Ops:               rotator,
		Clock:             app.Clock,
		Log:               log,
		Reconcile:         cfg.Reconcile,
		MinRotateInterval: cfg.Carrier.MinRotateInterval,
		NServerFallback:   cfg.NServerFallback,
	})
	if err != nil {
		return nil, err
	}

	engineCtx, stopEngine := context.WithCancel(context.WithoutCancel(ctx))
	app.OnClose(func(context.Context) error { stopEngine(); return nil })
	go func() {
		if err := engine.Run(engineCtx); err != nil && engineCtx.Err() == nil {
			log.Error("the reconcile engine stopped", "error", err.Error())
		}
	}()

	app.AddMetricsSource(&metricsCollector{
		nodeID:   cfg.NodeID,
		version:  buildVersion(),
		repos:    db,
		observer: engine,
	})

	return httpapi.New(httpapi.Deps{
		NodeID:            cfg.NodeID,
		Version:           buildVersion(),
		Repos:             db,
		Rotator:           rotator,
		Waiter:            rotator,
		DevOps:            ops,
		Bus:               app.Bus,
		Observer:          engine,
		Sessions:          sessions,
		Keys:              keys,
		Lockout:           lockout,
		Limiter:           ratelimit.New(ratelimit.DefaultLimit(), app.Clock.Now),
		Clock:             app.Clock,
		Log:               log,
		MinRotateInterval: cfg.Carrier.MinRotateInterval,
		SecureCookies:     secureCookies,
	})
}

func resolveSecureCookies(lookup func(string) (string, bool)) (bool, error) {
	v, ok := lookup("DONGLED_ALLOW_INSECURE_COOKIES")
	if !ok || v == "" {
		return true, nil
	}
	if v != "1" {
		return false, fmt.Errorf("invalid DONGLED_ALLOW_INSECURE_COOKIES value %q, expected \"1\"", v)
	}
	return false, nil
}

func policyFromConfig(cfg config.Config) rotate.Policy {
	return rotate.Policy{
		HardDeadline:       cfg.Carrier.HardDeadline,
		HoldEscalate:       append([]time.Duration(nil), cfg.Carrier.HoldEscalate...),
		WaitConnect:        cfg.Carrier.WaitConnect,
		PollInterval:       cfg.Carrier.PollInterval,
		VerifyTimeout:      cfg.Carrier.VerifyTimeout,
		MaxAttempts:        cfg.Carrier.MaxAttempts,
		RebootBudgetPerDay: cfg.Reconcile.RebootBudgetPerDay,
		RebootCooldown:     cfg.Reconcile.RebootCooldown,
		MinInterval:        cfg.Carrier.MinRotateInterval,
		MaxConcurrent:      cfg.Reconcile.MaxConcurrentRotate,
		Jitter:             cfg.Reconcile.RotateJitter,
	}
}

func panelSupervisor(cfg config.Config) (proxysup.Supervisor, error) {
	if cfg.Proxy == config.BackendFake {
		return nil, nil
	}
	return buildSupervisor(cfg)
}

func readSecret(prompt string) (string, error) {
	if v, ok := os.LookupEnv(EnvPassword); ok {
		return v, nil
	}
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

const EnvPassword = "DONGLED_PASSWORD"

func openPanelStore(ctx context.Context, cfg config.Config) (*store.Store, error) {
	sealer, err := loadSealer(cfg)
	if err != nil {
		return nil, err
	}
	s, err := store.Open(cfg.DBPath, sealer)
	if err != nil {
		return nil, err
	}
	if err := s.Migrate(ctx); err != nil {
		s.Close()
		return nil, err
	}
	if err := ensureNode(ctx, s, cfg); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func init() {
	Register(Command{
		Name:  "passwd",
		Usage: "set the password of a panel account, creating it when it does not exist",
		Run:   runPasswd,
	})
}

func runPasswd(ctx context.Context, cfg config.Config, args []string) error {
	username := "admin"
	if len(args) > 0 && args[0] != "" {
		username = args[0]
	}

	password, err := readSecret("password for " + username + ": ")
	if err != nil {
		return err
	}
	again, err := readSecret("repeat: ")
	if err != nil {
		return err
	}
	if password != again {
		return errors.New("passwd: the two entries do not match")
	}

	db, err := openPanelStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := auth.EnsureSchema(ctx, db.DB()); err != nil {
		return err
	}
	sessions := auth.NewSessions(db.DB(), cfg.SessionTTL, time.Now)
	if err := sessions.SetPassword(ctx, username, password); err != nil {
		return err
	}
	if err := sessions.RevokeUser(ctx, username); err != nil {
		return err
	}
	fmt.Printf("password set for %s, every open session of that account was signed out\n", username)
	return nil
}
