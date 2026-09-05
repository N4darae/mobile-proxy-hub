package rotate

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/n4darae/huawei-API/src/internal/device"
	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/eventbus"
	"github.com/n4darae/huawei-API/src/internal/fw"
	"github.com/n4darae/huawei-API/src/internal/reconcile"
	"github.com/n4darae/huawei-API/src/internal/store"
)

const (
	fenceReleaseTimeout = 5 * time.Second
	waitDisconnectCap   = 15 * time.Second
)

var (
	ErrOpInProgress = domain.ErrOpInProgress
	ErrSimLocked    = domain.ErrSimLocked
	ErrMinInterval  = errors.New("rotate: the minimum interval between rotations has not elapsed")
	ErrNoRepos      = errors.New("rotate: a store.Repos is required")
	ErrNoDevices    = errors.New("rotate: a device.Registry is required")
	ErrNoFirewall   = errors.New("rotate: a fw.Firewall is required")
	ErrNoRebooter   = errors.New("rotate: reboot escalation is not wired")
	ErrClosed       = errors.New("rotate: engine is shutting down")
)

var (
	errPollTimeout    = errors.New("rotate: the dongle did not reach the expected connection status")
	errRebootNotAllow = errors.New("rotate: the reboot budget for this dongle is spent")
)

type ConflictError struct {
	OperationID string
	SubjectType domain.SubjectType
	SubjectID   string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("rotate: operation %s is already live on %s:%s", e.OperationID, e.SubjectType, e.SubjectID)
}

func (e *ConflictError) Unwrap() error { return domain.ErrOpInProgress }

func (e *ConflictError) ActiveOperationID() string { return e.OperationID }

type TooSoonError struct {
	ProxyID     string
	RetryAfter  time.Duration
	MinInterval time.Duration
}

func (e *TooSoonError) Error() string {
	return fmt.Sprintf("rotate: proxy %s rotated less than %s ago, retry in %s", e.ProxyID, e.MinInterval, e.RetryAfter)
}

func (e *TooSoonError) Unwrap() []error { return []error{ErrMinInterval, domain.ErrRateLimited} }

type Request struct {
	ProxyID        string
	Trigger        domain.Trigger
	ActorType      domain.ActorType
	ActorID        string
	RequestID      string
	IdempotencyKey string
	AllowReboot    bool
}

type Rotator interface {
	Rotate(ctx context.Context, req Request) (*domain.Operation, error)
	Selftest(ctx context.Context, proxyID string) (SelftestResult, error)
}

type Rebooter interface {
	RebootAuto(ctx context.Context, dongleID, reason string) (domain.Operation, error)
}

type Deps struct {
	Repos  store.Repos
	Dev    device.Registry
	FW     fw.Firewall
	Probe  Prober
	Reboot Rebooter
	Bus    eventbus.Bus
	Clock  domain.Clock
	Policy Policy
	NodeID string
	NewID  func(prefix string) string
	Rand   func() float64
}

type Engine struct {
	deps           Deps
	pol            Policy
	sem            chan struct{}
	mu             sync.Mutex
	waiters        map[string]chan struct{}
	wg             sync.WaitGroup
	closed         bool
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

var (
	_ Rotator       = (*Engine)(nil)
	_ reconcile.Ops = (*Engine)(nil)
)

func New(d Deps) (*Engine, error) {
	if d.Repos == nil {
		return nil, ErrNoRepos
	}
	if d.Dev == nil {
		return nil, ErrNoDevices
	}
	if d.FW == nil {
		return nil, ErrNoFirewall
	}
	if d.Probe == nil {
		return nil, ErrProbeUnavailable
	}
	if d.Clock == nil {
		d.Clock = domain.SystemClock()
	}
	if d.NewID == nil {
		d.NewID = NewID
	}
	if d.Rand == nil {
		d.Rand = rand.Float64
	}
	pol := d.Policy
	if len(pol.HoldEscalate) == 0 && pol.MaxAttempts == 0 && pol.HardDeadline == 0 {
		pol = DefaultPolicy()
	}
	if err := pol.Validate(); err != nil {
		return nil, err
	}
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	return &Engine{
		deps:           d,
		pol:            pol,
		sem:            make(chan struct{}, pol.MaxConcurrent),
		waiters:        map[string]chan struct{}{},
		shutdownCtx:    shutdownCtx,
		shutdownCancel: shutdownCancel,
	}, nil
}

func (e *Engine) Policy() Policy { return e.pol }

func NewID(prefix string) string {
	var b [10]byte
	if _, err := crand.Read(b[:]); err != nil {
		binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixNano()))
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

type target struct {
	proxy  domain.Proxy
	slot   domain.SlotRow
	dongle domain.Dongle
	node   domain.Node
}

func (e *Engine) target(ctx context.Context, proxyID string) (target, error) {
	var t target
	px, err := e.deps.Repos.Proxies().Get(ctx, proxyID)
	if err != nil {
		return t, err
	}
	t.proxy = px
	row, err := e.deps.Repos.Slots().Get(ctx, px.SlotID)
	if err != nil {
		return t, err
	}
	t.slot = row
	node, err := e.deps.Repos.Nodes().Get(ctx, row.NodeID)
	if err != nil {
		return t, err
	}
	t.node = node
	if row.Occupied() {
		d, err := e.deps.Repos.Dongles().Get(ctx, *row.DongleID)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return t, err
		}
		t.dongle = d
	}
	return t, nil
}

func (e *Engine) Rotate(ctx context.Context, req Request) (*domain.Operation, error) {
	if strings.TrimSpace(req.ProxyID) == "" {
		return nil, fmt.Errorf("%w: rotate needs a proxy id", domain.ErrInvalid)
	}
	if req.Trigger == "" {
		req.Trigger = domain.TriggerAdminUI
	}
	if !req.Trigger.Valid() {
		return nil, fmt.Errorf("%w: trigger %q", domain.ErrInvalid, string(req.Trigger))
	}
	if req.ActorType == "" {
		req.ActorType = actorFor(req.Trigger)
	}

	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}

	t, err := e.target(ctx, req.ProxyID)
	if err != nil {
		return nil, err
	}
	if err := e.checkInterval(ctx, req.ProxyID); err != nil {
		return nil, err
	}
	if err := e.checkConflict(ctx, domain.SubjectProxy, req.ProxyID); err != nil {
		return nil, err
	}

	now := e.deps.Clock.Now()
	op := domain.Operation{
		ID:          e.deps.NewID("op"),
		Kind:        domain.OpRotate,
		SubjectType: domain.SubjectProxy,
		SubjectID:   req.ProxyID,
		State:       domain.OpPending,
		StartedAt:   domain.UnixMillis(now),
		DeadlineAt:  domain.UnixMillis(now.Add(e.pol.RowDeadline())),
		Trigger:     req.Trigger,
		ActorType:   req.ActorType,
		ActorID:     req.ActorID,
		RequestID:   req.RequestID,
	}
	if err := e.deps.Repos.Operations().Create(ctx, op); err != nil {
		if errors.Is(err, domain.ErrOpInProgress) {
			if live, lookupErr := e.deps.Repos.Operations().FindActive(ctx, domain.SubjectProxy, req.ProxyID); lookupErr == nil {
				return nil, &ConflictError{OperationID: live.ID, SubjectType: domain.SubjectProxy, SubjectID: req.ProxyID}
			}
		}
		return nil, err
	}
	e.publishOp(ctx, op, eventbus.EvOpUpdate)

	done := make(chan struct{})
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		_ = e.deps.Repos.Operations().Finish(ctx, op.ID, domain.OpCanceled, ErrClosed.Error(), "{}",
			domain.UnixMillis(e.deps.Clock.Now()))
		return nil, ErrClosed
	}
	e.waiters[op.ID] = done
	e.wg.Add(1)
	e.mu.Unlock()

	go func(op domain.Operation) {
		defer e.wg.Done()
		defer func() {
			e.mu.Lock()
			delete(e.waiters, op.ID)
			e.mu.Unlock()
			close(done)
		}()
		e.run(req, op, t)
	}(op)

	return &op, nil
}

func (e *Engine) Wait(ctx context.Context, operationID string) (domain.Operation, error) {
	e.mu.Lock()
	ch, ok := e.waiters[operationID]
	e.mu.Unlock()
	if ok {
		select {
		case <-ch:
		case <-ctx.Done():
			return domain.Operation{}, ctx.Err()
		}
	}
	return e.deps.Repos.Operations().Get(ctx, operationID)
}

func (e *Engine) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		e.shutdownCancel()
		return nil
	case <-ctx.Done():
		e.shutdownCancel()
		return ctx.Err()
	}
}

func (e *Engine) RecoverRotate(ctx context.Context, proxyID, reason string) (domain.Operation, error) {
	op, err := e.Rotate(ctx, Request{
		ProxyID:     proxyID,
		Trigger:     domain.TriggerAutoRecovery,
		ActorType:   domain.ActorSystem,
		ActorID:     reason,
		AllowReboot: true,
	})
	if err != nil {
		return domain.Operation{}, err
	}
	return *op, nil
}

func (e *Engine) RebootDongle(ctx context.Context, dongleID, reason string) (domain.Operation, error) {
	if e.deps.Reboot == nil {
		return domain.Operation{}, ErrNoRebooter
	}
	return e.deps.Reboot.RebootAuto(ctx, dongleID, reason)
}

func actorFor(t domain.Trigger) domain.ActorType {
	switch t {
	case domain.TriggerCustomerAPI:
		return domain.ActorAPIKey
	case domain.TriggerAutoRecovery:
		return domain.ActorSystem
	default:
		return domain.ActorAdmin
	}
}

func (e *Engine) checkInterval(ctx context.Context, proxyID string) error {
	if e.pol.MinInterval <= 0 {
		return nil
	}
	last, err := e.deps.Repos.Rotations().LastFor(ctx, proxyID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	elapsed := e.deps.Clock.Now().Sub(domain.FromUnixMillis(last.RequestedAt))
	if elapsed >= e.pol.MinInterval {
		return nil
	}
	return &TooSoonError{ProxyID: proxyID, RetryAfter: e.pol.MinInterval - elapsed, MinInterval: e.pol.MinInterval}
}

func (e *Engine) checkConflict(ctx context.Context, subject domain.SubjectType, id string) error {
	live, err := e.deps.Repos.Operations().FindActive(ctx, subject, id)
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return &ConflictError{OperationID: live.ID, SubjectType: subject, SubjectID: id}
}

type result struct {
	Reason      string
	Old         netip.Addr
	New         netip.Addr
	Changed     bool
	Attempts    int
	HoldMS      int
	StartedAt   time.Time
	DurationMS  int
	ConnsKilled int
	Note        string
	RebootOpID  string
	Err         error
}

type OpResult struct {
	Result      domain.RotationResult `json:"result"`
	IPChanged   bool                  `json:"ip_changed"`
	OldPublicIP string                `json:"old_public_ip,omitempty"`
	NewPublicIP string                `json:"new_public_ip,omitempty"`
	Attempts    int                   `json:"attempts"`
	HoldMS      int                   `json:"hold_ms"`
	DurationMS  int                   `json:"duration_ms"`
	ConnsKilled int                   `json:"conns_killed"`
	Reason      string                `json:"reason,omitempty"`
	Note        string                `json:"note,omitempty"`
	RebootOpID  string                `json:"reboot_operation_id,omitempty"`
}

func (e *Engine) run(req Request, op domain.Operation, t target) {
	ctx, cancel := context.WithTimeout(e.shutdownCtx, e.pol.RowDeadline()+e.pol.WaitConnect)
	defer cancel()

	var res result
	if err := e.acquire(ctx); err != nil {
		res = result{Reason: ReasonCanceled, Err: err, StartedAt: e.deps.Clock.Now()}
	} else {
		defer e.release()
		res = e.execute(ctx, &op, t)
	}
	finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(ctx), e.pol.FinishDeadline())
	defer finishCancel()
	e.finish(finishCtx, req, op, t, res)
}

func (e *Engine) acquire(ctx context.Context) error {
	select {
	case e.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if j := e.jitter(); j > 0 {
		if err := e.deps.Clock.Sleep(ctx, j); err != nil {
			<-e.sem
			return err
		}
	}
	return nil
}

func (e *Engine) release() { <-e.sem }

func (e *Engine) jitter() time.Duration {
	if e.pol.Jitter <= 0 {
		return 0
	}
	return time.Duration(e.deps.Rand() * float64(e.pol.Jitter))
}

func (e *Engine) execute(ctx context.Context, op *domain.Operation, t target) result {
	start := e.deps.Clock.Now()
	deadline := start.Add(e.pol.HardDeadline)
	res := result{StartedAt: start}

	e.step(ctx, op, domain.StepPrecheck)

	if !t.slot.Occupied() {
		return failed(res, ReasonSlotEmpty, fmt.Errorf("%w: slot %d holds no dongle", domain.ErrNotFound, t.slot.Slot.Int()))
	}
	slot := t.slot.Slot
	dev, err := e.deps.Dev.ForSlot(ctx, slot)
	if err != nil {
		return failed(res, ReasonDeviceUnreachable, err)
	}

	sim, err := dev.PinStatus(ctx)
	if err != nil {
		return failed(res, ReasonDeviceUnreachable, err)
	}
	if sim.Locked() {
		return failed(res, ReasonSimLocked, fmt.Errorf("%w: sim state %d", domain.ErrSimLocked, int(sim)))
	}

	if p, err := e.probeEgress(ctx, slot.HostIP(), t.node.PublicHost); err != nil {
		if errors.Is(err, ErrProbeEgressLeak) {
			res.New = p.IP
			return failed(res, ReasonEgressLeak, err)
		}
		if st, serr := dev.Status(ctx); serr == nil {
			res.Old = st.WanIP
		}
	} else {
		res.Old = p.IP
	}

	guard := &fenceGuard{fw: e.deps.FW, iface: slot.IfaceName()}
	defer guard.release()

	for attempt := 1; attempt <= e.pol.MaxAttempts; attempt++ {
		remaining := deadline.Sub(e.deps.Clock.Now())
		if !e.pol.AttemptFits(remaining, attempt) {
			if attempt == 1 {
				return failed(res, ReasonDeadline, fmt.Errorf("%w: %s left of the hard deadline", domain.ErrExpired, remaining))
			}
			break
		}
		res.Attempts = attempt
		hold := e.pol.HoldFor(attempt)
		res.HoldMS = int(hold / time.Millisecond)

		killed, note, err := e.cycle(ctx, op, dev, guard, slot, hold)
		res.ConnsKilled += killed
		res.Note = joinNote(res.Note, note)
		if err != nil {
			if errors.Is(err, fw.ErrUnknownIface) || errors.Is(err, errFenceFailed) {
				return failed(res, ReasonFenceFailed, err)
			}
			if errors.Is(err, errPollTimeout) && attempt < e.pol.MaxAttempts {
				continue
			}
			if errors.Is(err, errPollTimeout) {
				return failed(res, ReasonNoDataSession, err)
			}
			return failed(res, ReasonDeviceUnreachable, err)
		}

		e.step(ctx, op, domain.StepVerify)
		p, perr := e.probeEgress(ctx, slot.HostIP(), t.node.PublicHost)
		if perr != nil {
			if errors.Is(perr, ErrProbeEgressLeak) {
				res.New = p.IP
				return failed(res, ReasonEgressLeak, perr)
			}
			if attempt < e.pol.MaxAttempts {
				continue
			}
			return failed(res, ReasonProbeFailed, perr)
		}
		res.New = p.IP
		if p.IP.IsValid() && res.Old.IsValid() && p.IP != res.Old {
			res.Changed = true
			res.Reason = ReasonChanged
			e.step(ctx, op, domain.StepDone)
			return res
		}
	}

	res.Reason = ReasonUnchanged
	return res
}

var errFenceFailed = errors.New("rotate: the interface could not be fenced")

func (e *Engine) cycle(ctx context.Context, op *domain.Operation, dev device.Device, guard *fenceGuard, slot domain.Slot, hold time.Duration) (killed int, note string, err error) {
	e.step(ctx, op, domain.StepFence)
	if ferr := guard.fence(ctx); ferr != nil {
		return 0, "", fmt.Errorf("%w: %v", errFenceFailed, ferr)
	}
	killed, kerr := e.deps.FW.KillSockets(ctx, slot.HostIP())
	flushed, cerr := e.deps.FW.FlushConntrack(ctx, slot.HostIP())
	note = fenceNote(kerr, cerr, flushed)

	dataOff := false
	defer func() {
		if !dataOff {
			return
		}
		note = joinNote(note, e.restoreDataSession(dev))
	}()

	e.step(ctx, op, domain.StepDataOff)
	if err := dev.DataSwitch(ctx, false); err != nil {
		return killed, note, err
	}
	dataOff = true

	if err := e.pollConn(ctx, dev, device.ConnDisconnected, minDuration(e.pol.WaitConnect, waitDisconnectCap)); err != nil {
		if !errors.Is(err, errPollTimeout) {
			return killed, note, err
		}
		note = joinNote(note, "data session did not report 902 before the hold")
	}

	e.step(ctx, op, domain.StepHold)
	if err := e.deps.Clock.Sleep(ctx, hold); err != nil {
		return killed, note, err
	}

	e.step(ctx, op, domain.StepDataOn)
	if err := dev.DataSwitch(ctx, true); err != nil {
		return killed, note, err
	}
	dataOff = false

	e.step(ctx, op, domain.StepWaitConnect)
	if err := e.pollConn(ctx, dev, device.ConnConnected, e.pol.WaitConnect); err != nil {
		return killed, note, err
	}

	e.step(ctx, op, domain.StepUnfence)
	if err := guard.unfence(ctx); err != nil {
		return killed, note, err
	}
	return killed, note, nil
}

func (e *Engine) restoreDataSession(dev device.Device) string {
	back, cancel := context.WithTimeout(context.Background(), e.pol.WaitConnect)
	defer cancel()
	if err := dev.DataSwitch(back, true); err != nil {
		return "the aborted rotation left mobile data off and switching it back on failed: " + err.Error()
	}
	return "mobile data was switched back on after the rotation aborted"
}

func (e *Engine) pollConn(ctx context.Context, dev device.Device, want device.ConnStatus, budget time.Duration) error {
	deadline := e.deps.Clock.Now().Add(budget)
	var last error
	var seen device.ConnStatus
	for {
		st, err := dev.Status(ctx)
		if err == nil {
			seen = st.ConnectionStatus
			if st.ConnectionStatus == want {
				return nil
			}
		} else {
			last = err
		}
		if !e.deps.Clock.Now().Before(deadline) {
			if last != nil {
				return last
			}
			return fmt.Errorf("%w: status %d after %s, want %d", errPollTimeout, int(seen), budget, int(want))
		}
		if err := e.deps.Clock.Sleep(ctx, e.pol.PollInterval); err != nil {
			return err
		}
	}
}

func (e *Engine) step(ctx context.Context, op *domain.Operation, s domain.RotateStep) {
	op.State = domain.OpRunning
	op.Step = string(s)
	op.Pct = StepPct(s)
	if err := e.deps.Repos.Operations().Progress(ctx, op.ID, domain.OpRunning, op.Step, op.Pct); err != nil {
		return
	}
	e.publishOp(ctx, *op, eventbus.EvOpUpdate)
}

func (e *Engine) finish(ctx context.Context, req Request, op domain.Operation, t target, res result) {
	now := e.deps.Clock.Now()
	if !res.StartedAt.IsZero() {
		res.DurationMS = int(now.Sub(res.StartedAt) / time.Millisecond)
	}

	rot := domain.RotationFailed
	state := domain.OpFailed
	errMsg := res.Reason
	switch {
	case res.Changed:
		rot, state, errMsg = domain.RotationChanged, domain.OpSucceeded, ""
	case res.Reason == ReasonUnchanged:
		rot, state, errMsg = domain.RotationUnchanged, domain.OpFailed, ReasonUnchanged
	}

	if rot == domain.RotationUnchanged && req.AllowReboot {
		if id, err := e.escalateReboot(ctx, t.dongle.ID); err == nil {
			res.RebootOpID = id
		}
	}

	payload := OpResult{
		Result:      rot,
		IPChanged:   res.Changed,
		OldPublicIP: addrText(res.Old),
		NewPublicIP: addrText(res.New),
		Attempts:    res.Attempts,
		HoldMS:      res.HoldMS,
		DurationMS:  res.DurationMS,
		ConnsKilled: res.ConnsKilled,
		Reason:      res.Reason,
		Note:        res.Note,
		RebootOpID:  res.RebootOpID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte("{}")
	}

	detail := ""
	if res.Err != nil {
		detail = res.Err.Error()
	}
	_ = e.deps.Repos.Rotations().Create(ctx, domain.Rotation{
		ID:          e.deps.NewID("rot"),
		OperationID: op.ID,
		ProxyID:     op.SubjectID,
		RequestedAt: domain.UnixMillis(res.StartedAt),
		DurationMS:  res.DurationMS,
		OldPublicIP: res.Old,
		NewPublicIP: res.New,
		IPChanged:   res.Changed,
		Result:      rot,
		Trigger:     op.Trigger,
		RequestID:   op.RequestID,
		HoldMS:      res.HoldMS,
		Attempts:    res.Attempts,
		Error:       detail,
	})

	_ = e.deps.Repos.Operations().Finish(ctx, op.ID, state, errMsg, string(body), domain.UnixMillis(now))

	op.State = state
	op.Error = errMsg
	op.ResultJSON = string(body)
	op.Pct = 100
	finished := domain.UnixMillis(now)
	op.FinishedAt = &finished
	e.publishOp(ctx, op, eventbus.EvOpDone)
}

func (e *Engine) escalateReboot(ctx context.Context, dongleID string) (string, error) {
	if e.deps.Reboot == nil {
		return "", ErrNoRebooter
	}
	if dongleID == "" {
		return "", domain.ErrNotFound
	}
	ok, err := e.RebootAllowed(ctx, dongleID)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errRebootNotAllow
	}
	op, err := e.deps.Reboot.RebootAuto(ctx, dongleID, ReasonUnchanged)
	if err != nil {
		return "", err
	}
	return op.ID, nil
}

func (e *Engine) RebootAllowed(ctx context.Context, dongleID string) (bool, error) {
	if e.pol.RebootBudgetPerDay <= 0 {
		return false, nil
	}
	now := e.deps.Clock.Now()
	ops, err := e.deps.Repos.Operations().List(ctx, store.OperationFilter{
		Kind:        domain.OpReboot,
		SubjectType: domain.SubjectDongle,
		SubjectID:   dongleID,
		SinceMS:     domain.UnixMillis(startOfDay(now)),
	})
	if err != nil {
		return false, err
	}
	if len(ops) >= e.pol.RebootBudgetPerDay {
		return false, nil
	}
	for _, o := range ops {
		if now.Sub(domain.FromUnixMillis(o.StartedAt)) < e.pol.RebootCooldown {
			return false, nil
		}
	}
	return true, nil
}

func startOfDay(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

type opPayload struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	State       string `json:"state"`
	Step        string `json:"step"`
	Pct         int    `json:"pct"`
	StartedAt   int64  `json:"started_at"`
	DeadlineAt  int64  `json:"deadline_at"`
	FinishedAt  *int64 `json:"finished_at,omitempty"`
	Error       string `json:"error,omitempty"`
	Trigger     string `json:"trigger"`
	ActorType   string `json:"actor_type,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
}

func (e *Engine) publishOp(ctx context.Context, op domain.Operation, kind eventbus.EventType) {
	if e.deps.Bus == nil {
		return
	}
	ev, err := eventbus.NewEvent(e.deps.NodeID, kind, op.ID, opPayload{
		ID:          op.ID,
		Kind:        string(op.Kind),
		SubjectType: string(op.SubjectType),
		SubjectID:   op.SubjectID,
		State:       string(op.State),
		Step:        op.Step,
		Pct:         op.Pct,
		StartedAt:   op.StartedAt,
		DeadlineAt:  op.DeadlineAt,
		FinishedAt:  op.FinishedAt,
		Error:       op.Error,
		Trigger:     string(op.Trigger),
		ActorType:   string(op.ActorType),
		RequestID:   op.RequestID,
	})
	if err != nil {
		return
	}
	_ = e.deps.Bus.Publish(ctx, ev)
}

type fenceGuard struct {
	fw     fw.Firewall
	iface  string
	mu     sync.Mutex
	fenced bool
}

func (g *fenceGuard) fence(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.fw.Fence(ctx, g.iface); err != nil {
		return err
	}
	g.fenced = true
	return nil
}

func (g *fenceGuard) unfence(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.fenced {
		return nil
	}
	err := g.fw.Unfence(ctx, g.iface)
	if err != nil && !errors.Is(err, fw.ErrUnknownIface) {
		return err
	}
	g.fenced = false
	return nil
}

func (g *fenceGuard) release() {
	ctx, cancel := context.WithTimeout(context.Background(), fenceReleaseTimeout)
	defer cancel()
	_ = g.unfence(ctx)
}

func failed(res result, reason string, err error) result {
	res.Reason = reason
	res.Err = err
	return res
}

func fenceNote(killErr, flushErr error, flushed int) string {
	note := ""
	if killErr != nil && !errors.Is(killErr, domain.ErrNotImplemented) {
		note = joinNote(note, "kill sockets: "+killErr.Error())
	}
	if flushErr != nil && !errors.Is(flushErr, domain.ErrNotImplemented) {
		note = joinNote(note, "flush conntrack: "+flushErr.Error())
	}
	if errors.Is(killErr, domain.ErrNotImplemented) || errors.Is(flushErr, domain.ErrNotImplemented) {
		note = joinNote(note, "firewall backend is a fake, sockets were not killed")
	}
	if flushed > 0 {
		note = joinNote(note, "conntrack entries flushed: "+itoa(flushed))
	}
	return note
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
