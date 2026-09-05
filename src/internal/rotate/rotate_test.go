package rotate

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/n4darae/huawei-API/src/internal/device"
	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/fw"
	"github.com/n4darae/huawei-API/src/internal/store"
)

func publicSteps() []string {
	out := make([]string, 0, len(domain.RotateSteps()))
	for _, s := range domain.RotateSteps() {
		out = append(out, string(s))
	}
	return out
}

func TestRotateEmitsTheExactPublicStepSequence(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second})

	op, err := h.rotate(Request{ProxyID: proxyID(1), Trigger: domain.TriggerCustomerAPI})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if op.State != domain.OpSucceeded {
		t.Fatalf("operation state is %q with error %q, want succeeded", op.State, op.Error)
	}
	got := h.steps(proxyID(1))
	want := publicSteps()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("step sequence is %v, want %v", got, want)
	}
	res := h.result(op)
	if res.Result != domain.RotationChanged || !res.IPChanged {
		t.Fatalf("result json is %+v, want a changed rotation", res)
	}
}

func TestFenceKillFlushRunInOrderAndUnfenceIsTheLastCall(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second})

	if _, err := h.rotate(Request{ProxyID: proxyID(1)}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	iface := domain.Slot(1).IfaceName()
	src := domain.Slot(1).HostIP().String()
	want := []string{"fence:" + iface, "kill:" + src, "flush:" + src, "unfence:" + iface}
	if got := h.fw.Calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("firewall call order is %v, want %v", got, want)
	}
	if fenced, err := h.fw.IsFenced(context.Background(), iface); err != nil || fenced {
		t.Fatalf("interface is still fenced after the rotation (fenced=%v err=%v)", fenced, err)
	}
}

func TestFencingIsUnconditionalAndSurvivesAFailedVerification(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: 2 * time.Hour})

	if _, err := h.rotate(Request{ProxyID: proxyID(1)}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	iface := domain.Slot(1).IfaceName()
	calls := h.fw.Calls()
	fences, unfences := 0, 0
	for _, c := range calls {
		switch c {
		case "fence:" + iface:
			fences++
		case "unfence:" + iface:
			unfences++
		}
	}
	if fences != h.pol.MaxAttempts || unfences != h.pol.MaxAttempts {
		t.Fatalf("fenced %d times and unfenced %d times over %d attempts: %v", fences, unfences, h.pol.MaxAttempts, calls)
	}
}

func TestHoldLadderEscalatesUntilTheCarrierGrantsANewIP(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: 10 * time.Second})

	op, err := h.rotate(Request{ProxyID: proxyID(1)})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if op.State != domain.OpSucceeded {
		t.Fatalf("operation state is %q (%q), want succeeded on the second rung", op.State, op.Error)
	}
	res := h.result(op)
	if res.Attempts != 2 {
		t.Fatalf("rotation used %d attempts, want 2: a 6s hold must not win against a 10s carrier hold", res.Attempts)
	}
	if want := int(h.pol.HoldEscalate[1] / time.Millisecond); res.HoldMS != want {
		t.Fatalf("winning hold was %dms, want the second rung %dms", res.HoldMS, want)
	}
	rot := h.lastRotation(proxyID(1))
	if rot.Result != domain.RotationChanged || !rot.IPChanged {
		t.Fatalf("rotations row is %+v, want a changed rotation", rot)
	}
	if rot.OldPublicIP == rot.NewPublicIP {
		t.Fatalf("rotations row recorded the same address twice: %s", rot.OldPublicIP)
	}
}

func TestASingleRungIsEnoughWhenTheCarrierIsFast(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: 2 * time.Second})

	op, err := h.rotate(Request{ProxyID: proxyID(1)})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if res := h.result(op); res.Attempts != 1 {
		t.Fatalf("rotation used %d attempts, want 1", res.Attempts)
	}
}

func TestProbeEgressLeakIsAHardFailureAndNeverUnchanged(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second})
	h.probe.setLeak(testNodeIP)

	op, err := h.rotate(Request{ProxyID: proxyID(1)})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if op.State != domain.OpFailed {
		t.Fatalf("operation state is %q, want failed when the probe leaves via the host uplink", op.State)
	}
	if op.Error != ReasonEgressLeak {
		t.Fatalf("operation error is %q, want %q", op.Error, ReasonEgressLeak)
	}
	res := h.result(op)
	if res.Result == domain.RotationUnchanged {
		t.Fatalf("an egress leak was reported as %q; a host without a dongle would look like a working product", res.Result)
	}
	if res.Result != domain.RotationFailed {
		t.Fatalf("result json is %+v, want a failed rotation", res)
	}
	rot := h.lastRotation(proxyID(1))
	if rot.Result != domain.RotationFailed || rot.IPChanged {
		t.Fatalf("rotations row is %+v, want a failed rotation", rot)
	}
	if len(h.fw.Calls()) != 0 {
		t.Fatalf("a leaking route dropped the customer session before it was detected: %v", h.fw.Calls())
	}
}

func TestAnEgressLeakDetectedAtVerifyStillFailsAndUnfences(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second})
	h.probe.setLeakAfter(testNodeIP, 1)

	op, err := h.rotate(Request{ProxyID: proxyID(1)})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if op.State != domain.OpFailed || op.Error != ReasonEgressLeak {
		t.Fatalf("operation is %q/%q, want failed with %q", op.State, op.Error, ReasonEgressLeak)
	}
	if res := h.result(op); res.Result != domain.RotationFailed {
		t.Fatalf("result json is %+v, want a failed rotation", res)
	}
	iface := domain.Slot(1).IfaceName()
	if fenced, err := h.fw.IsFenced(context.Background(), iface); err != nil || fenced {
		t.Fatalf("interface stayed fenced after a leak failure (fenced=%v err=%v)", fenced, err)
	}
}

func TestCheckLeakOnlyFiresOnTheNodePublicHost(t *testing.T) {
	requireErrorIs(t, CheckLeak(testNodeIP, testNodeIP), ErrProbeEgressLeak, "CheckLeak on the public host")
	if err := CheckLeak(domain.Slot(1).HostIP(), testNodeIP); err != nil {
		t.Fatalf("CheckLeak on a dongle address returned %v, want nil", err)
	}
}

func TestPinLockedSimIsARefusalWithNoFenceAndNoReboot(t *testing.T) {
	states := map[string]device.SimState{
		"pin_required": device.SimStatePINRequired,
		"puk_required": device.SimStatePUKRequired,
		"pin_checking": device.SimStatePINChecking,
	}
	for name, state := range states {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{HoldToNewIP: time.Second})
			h.farm.Device(1).SetPinLocked(state)

			op, err := h.rotate(Request{ProxyID: proxyID(1), AllowReboot: true})
			if err != nil {
				t.Fatalf("Rotate: %v", err)
			}
			if op.State != domain.OpFailed || op.Error != ReasonSimLocked {
				t.Fatalf("operation is %q/%q, want failed with %q", op.State, op.Error, ReasonSimLocked)
			}
			if len(h.fw.Calls()) != 0 {
				t.Fatalf("a pin locked sim still dropped the customer session: %v", h.fw.Calls())
			}
			if h.probe.sourceCalls() != 0 {
				t.Fatalf("a pin locked sim was probed %d times before the refusal", h.probe.sourceCalls())
			}
			if calls := h.boot.Calls(); len(calls) != 0 {
				t.Fatalf("a pin locked sim was escalated to a reboot: %v", calls)
			}
			rot := h.lastRotation(proxyID(1))
			if rot.Result != domain.RotationFailed {
				t.Fatalf("rotations row is %+v, want a failed rotation", rot)
			}
		})
	}
}

func TestUnchangedIsRecordedAsAFailure(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: 2 * time.Hour})

	op, err := h.rotate(Request{ProxyID: proxyID(1)})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if op.State != domain.OpFailed || op.Error != ReasonUnchanged {
		t.Fatalf("operation is %q/%q, want failed with %q", op.State, op.Error, ReasonUnchanged)
	}
	res := h.result(op)
	if res.Result != domain.RotationUnchanged || res.IPChanged {
		t.Fatalf("result json is %+v, want unchanged with ip_changed false", res)
	}
	if res.Attempts != h.pol.MaxAttempts {
		t.Fatalf("rotation gave up after %d attempts, want the full ladder of %d", res.Attempts, h.pol.MaxAttempts)
	}
	rot := h.lastRotation(proxyID(1))
	if rot.Result != domain.RotationUnchanged || rot.IPChanged {
		t.Fatalf("rotations row is %+v, want unchanged", rot)
	}
	if rot.OldPublicIP != rot.NewPublicIP {
		t.Fatalf("rotations row claims %s became %s while reporting unchanged", rot.OldPublicIP, rot.NewPublicIP)
	}
}

func TestUnchangedEscalatesToARebootOnlyWhenAllowedAndInBudget(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: 2 * time.Hour})

	op, err := h.rotate(Request{ProxyID: proxyID(1), Trigger: domain.TriggerAutoRecovery, ActorID: "data session down", AllowReboot: true})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	calls := h.boot.Calls()
	if len(calls) != 1 {
		t.Fatalf("reboot escalation ran %d times, want exactly one: %v", len(calls), calls)
	}
	if res := h.result(op); res.RebootOpID == "" {
		t.Fatalf("result json is %+v, want the reboot operation id recorded", res)
	}

	if _, err := h.rotate(Request{ProxyID: proxyID(1), Trigger: domain.TriggerAutoRecovery, AllowReboot: true}); err != nil {
		t.Fatalf("second Rotate: %v", err)
	}
	if calls := h.boot.Calls(); len(calls) != 1 {
		t.Fatalf("reboot cooldown was ignored, escalations: %v", calls)
	}
}

func TestUnchangedDoesNotRebootWhenTheCallerDidNotAllowIt(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: 2 * time.Hour})

	if _, err := h.rotate(Request{ProxyID: proxyID(1), Trigger: domain.TriggerCustomerAPI}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if calls := h.boot.Calls(); len(calls) != 0 {
		t.Fatalf("a customer rotate rebooted the dongle: %v", calls)
	}
}

func TestSecondRotateOnTheSameProxyIsAConflictCarryingTheLiveOperationID(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second})
	gate := make(chan struct{})
	h.probe.setGate(gate)

	ctx := context.Background()
	first, err := h.eng.Rotate(ctx, Request{ProxyID: proxyID(1)})
	if err != nil {
		t.Fatalf("first Rotate: %v", err)
	}
	waitFor(t, func() bool { return h.probe.sourceCalls() > 0 })

	_, err = h.eng.Rotate(ctx, Request{ProxyID: proxyID(1)})
	requireErrorIs(t, err, domain.ErrOpInProgress, "concurrent Rotate")

	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("concurrent Rotate returned %v, want a *ConflictError", err)
	}
	if conflict.OperationID != first.ID {
		t.Fatalf("conflict carries operation %q, want the live %q", conflict.OperationID, first.ID)
	}
	var accessor interface{ ActiveOperationID() string }
	if !errors.As(err, &accessor) || accessor.ActiveOperationID() != first.ID {
		t.Fatalf("conflict does not expose the live operation id through the shared accessor")
	}

	close(gate)
	wait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := h.eng.Wait(wait, first.ID); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}

func TestMinIntervalRejectsARepeatRotate(t *testing.T) {
	pol := testPolicy()
	pol.MinInterval = 60 * time.Second
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second, Policy: &pol})

	if _, err := h.rotate(Request{ProxyID: proxyID(1)}); err != nil {
		t.Fatalf("first Rotate: %v", err)
	}
	_, err := h.eng.Rotate(context.Background(), Request{ProxyID: proxyID(1)})
	requireErrorIs(t, err, ErrMinInterval, "repeat Rotate")
	requireErrorIs(t, err, domain.ErrRateLimited, "repeat Rotate")

	var soon *TooSoonError
	if !errors.As(err, &soon) {
		t.Fatalf("repeat Rotate returned %v, want a *TooSoonError", err)
	}
	if soon.RetryAfter <= 0 || soon.RetryAfter > pol.MinInterval {
		t.Fatalf("retry after is %s, want a positive value inside the %s window", soon.RetryAfter, pol.MinInterval)
	}
}

func TestFarmWideConcurrencyIsCappedAtFour(t *testing.T) {
	pol := testPolicy()
	pol.MaxConcurrent = 4
	h := newHarness(t, harnessOptions{Slots: 8, HoldToNewIP: time.Second, Policy: &pol})

	gate := make(chan struct{})
	h.probe.setGate(gate)

	ctx := context.Background()
	ops := make([]string, 0, 8)
	for i := 1; i <= 8; i++ {
		op, err := h.eng.Rotate(ctx, Request{ProxyID: proxyID(domain.Slot(i))})
		if err != nil {
			t.Fatalf("Rotate slot %d: %v", i, err)
		}
		ops = append(ops, op.ID)
	}

	waitFor(t, func() bool { return h.probe.inflight.Load() == 4 })
	time.Sleep(150 * time.Millisecond)
	if got := h.probe.maxFlight.Load(); got != 4 {
		t.Fatalf("%d rotations were in flight at once, want the farm cap of %d", got, pol.MaxConcurrent)
	}

	close(gate)
	for _, id := range ops {
		wait, cancel := context.WithTimeout(ctx, 60*time.Second)
		op, err := h.eng.Wait(wait, id)
		cancel()
		if err != nil {
			t.Fatalf("Wait %s: %v", id, err)
		}
		if op.State != domain.OpSucceeded {
			t.Fatalf("operation %s finished %q (%q), want succeeded", id, op.State, op.Error)
		}
	}
	if got := h.probe.maxFlight.Load(); got > int32(pol.MaxConcurrent) {
		t.Fatalf("the farm cap was breached, peak concurrency was %d", got)
	}
}

func TestRecoverRotateWritesAnAutoRecoveryOperation(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second})

	op, err := h.eng.RecoverRotate(context.Background(), proxyID(1), "dongle data session is not connected")
	if err != nil {
		t.Fatalf("RecoverRotate: %v", err)
	}
	if op.Trigger != domain.TriggerAutoRecovery {
		t.Fatalf("recovery operation trigger is %q, want auto_recovery", op.Trigger)
	}
	if op.ActorType != domain.ActorSystem {
		t.Fatalf("recovery operation actor is %q, want system", op.ActorType)
	}
	if op.ActorID == "" {
		t.Fatalf("recovery operation does not record why the panel started it")
	}
	wait, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	final, err := h.eng.Wait(wait, op.ID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	rows, err := h.db.Operations().List(context.Background(), store.OperationFilter{
		Kind:        domain.OpRotate,
		Trigger:     domain.TriggerAutoRecovery,
		SubjectType: domain.SubjectProxy,
		SubjectID:   proxyID(1),
	})
	if err != nil || len(rows) != 1 {
		t.Fatalf("auto recovery wrote %d operations rows (err %v), want exactly one piece of evidence", len(rows), err)
	}
	if rows[0].ID != final.ID {
		t.Fatalf("operations row %q does not match the returned operation %q", rows[0].ID, final.ID)
	}
}

func TestRebootDongleWithoutARebooterIsAnError(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second, NoRebooter: true})
	_, err := h.eng.RebootDongle(context.Background(), dongleID(1), "unreachable")
	requireErrorIs(t, err, ErrNoRebooter, "RebootDongle without a rebooter")
}

func TestFenceGuardIsIdempotentAndToleratesAnUnknownInterface(t *testing.T) {
	ctx := context.Background()
	f := newRecFW()
	g := &fenceGuard{fw: f, iface: "dg01"}

	if err := g.fence(ctx); err != nil {
		t.Fatalf("fence: %v", err)
	}
	if err := g.unfence(ctx); err != nil {
		t.Fatalf("first unfence: %v", err)
	}
	if err := g.unfence(ctx); err != nil {
		t.Fatalf("second unfence: %v", err)
	}
	g.release()
	want := []string{"fence:dg01", "unfence:dg01"}
	if got := f.Calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("guard made %v calls, want %v", got, want)
	}

	f.unknownIface = true
	if err := g.fence(ctx); err != nil {
		t.Fatalf("second fence: %v", err)
	}
	if err := g.unfence(ctx); err != nil {
		t.Fatalf("unfence on an unknown interface returned %v, want it treated as already unfenced", err)
	}
	if errors.Is(nil, fw.ErrUnknownIface) {
		t.Fatal("unreachable")
	}
}

func TestFenceFailureAbortsTheRotationBeforeTheDataSessionIsTouched(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second})
	h.fw.failFence = errors.New("nft add element failed")

	op, err := h.rotate(Request{ProxyID: proxyID(1)})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if op.State != domain.OpFailed || op.Error != ReasonFenceFailed {
		t.Fatalf("operation is %q/%q, want failed with %q", op.State, op.Error, ReasonFenceFailed)
	}
	if h.farm.Device(1).ConnectionStatus() != device.ConnConnected {
		t.Fatalf("the data session was dropped even though fencing failed")
	}
}

func TestARotationAbortedDuringTheHoldSwitchesMobileDataBackOn(t *testing.T) {
	pol := testPolicy()
	pol.HoldEscalate = []time.Duration{7 * time.Second}
	pol.MaxAttempts = 1
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second, Policy: &pol, HoldFails: context.Canceled})

	op, err := h.rotate(Request{ProxyID: proxyID(1)})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if op.State != domain.OpFailed {
		t.Fatalf("operation is %q/%q, want a failed rotation", op.State, op.Error)
	}
	if !h.farm.Device(1).DataOn() {
		t.Fatalf("the aborted rotation left mobile data switched off on slot 1")
	}
	if res := h.result(op); res.Note == "" {
		t.Fatalf("the restored data session left no trace in %+v", res)
	}
}

func TestAFakeFirewallIsRecordedInTheResultInsteadOfPassingSilently(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second})
	h.fw.notImpl = true

	op, err := h.rotate(Request{ProxyID: proxyID(1)})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	res := h.result(op)
	if res.Note == "" {
		t.Fatalf("a firewall backend that killed no sockets left no trace in %+v", res)
	}
}

func TestSelftestReportsBothListenersAndTheEgressAddress(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second})

	got, err := h.eng.Selftest(context.Background(), proxyID(1))
	if err != nil {
		t.Fatalf("Selftest: %v", err)
	}
	if !got.SocksOK || !got.HTTPOK || got.Error != "" {
		t.Fatalf("selftest is %+v, want both listeners healthy", got)
	}
	if got.EgressIP != h.farm.Device(1).PublicIP() {
		t.Fatalf("selftest reports egress %s, want the dongle public address %s", got.EgressIP, h.farm.Device(1).PublicIP())
	}
	if !got.OK() {
		t.Fatalf("selftest %+v does not report OK", got)
	}
}

func TestSelftestFlagsAnEgressLeak(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second})
	h.probe.setLeak(testNodeIP)

	got, err := h.eng.Selftest(context.Background(), proxyID(1))
	if err != nil {
		t.Fatalf("Selftest: %v", err)
	}
	if got.Error != ReasonEgressLeak {
		t.Fatalf("selftest error is %q, want %q", got.Error, ReasonEgressLeak)
	}
	if got.OK() {
		t.Fatalf("a leaking selftest reported OK: %+v", got)
	}
}

func TestRotateRefusesAnUnknownProxy(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second})
	_, err := h.eng.Rotate(context.Background(), Request{ProxyID: "nope"})
	requireErrorIs(t, err, domain.ErrNotFound, "Rotate on a missing proxy")
}

func TestRotateRefusesAnEmptyProxyID(t *testing.T) {
	h := newHarness(t, harnessOptions{HoldToNewIP: time.Second})
	_, err := h.eng.Rotate(context.Background(), Request{ProxyID: "  "})
	requireErrorIs(t, err, domain.ErrInvalid, "Rotate without a proxy id")
}

func TestNewRefusesAnEngineWithoutAProbe(t *testing.T) {
	_, err := New(Deps{Repos: nil})
	requireErrorIs(t, err, ErrNoRepos, "New without repos")
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition never became true")
}
