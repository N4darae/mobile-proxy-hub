package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"

	"github.com/n4darae/huawei-API/src/internal/domain"
)

var (
	ErrInvalidSlot        = errors.New("netcfg: invalid slot")
	ErrNoIDPath           = errors.New("netcfg: id path is required to render a link match")
	ErrGlobalNotReady     = errors.New("netcfg: EnsureGlobal must run before ApplySlot")
	ErrIDPathNotObserved  = errors.New("netcfg: id path is not reported by any link")
	ErrMACMismatch        = errors.New("netcfg: observed mac does not match the enrolled mac")
	ErrNoPublicHost       = errors.New("netcfg: at least one public host is required")
	ErrBadPublicHost      = errors.New("netcfg: public host must be a specific unicast address")
	ErrMalformedNetlink   = errors.New("netcfg: malformed netlink message")
	ErrTruncatedNetlink   = errors.New("netcfg: netlink datagram did not fit the receive buffer")
	ErrUnsupportedFamily  = errors.New("netcfg: unsupported address family")
	ErrProbeDstUnroutable = errors.New("netcfg: invariant probe destination is not routable")
)

type Exec func(ctx context.Context, name string, args ...string) ([]byte, error)

func SystemExec(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return out, &CommandError{Name: name, Args: args, Output: string(out), Err: err}
	}
	return out, nil
}

type CommandError struct {
	Name   string
	Args   []string
	Output string
	Err    error
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("netcfg: %s %s: %v: %s", e.Name, strings.Join(e.Args, " "), e.Err, strings.TrimSpace(e.Output))
}

func (e *CommandError) Unwrap() error { return e.Err }

var absentSignatures = []string{
	"cannot find device",
	"cannot find requested address",
	"cannot assign requested address",
	"no such device",
	"no such file or directory",
	"no such process",
	"no such object",
	"does not exist",
	"link not found",
	"unknown interface",
	"could not find",
	"not found",
}

func IsAbsent(err error) bool {
	if err == nil {
		return false
	}
	for _, e := range []error{syscall.ENOENT, syscall.ENODEV, syscall.EADDRNOTAVAIL, syscall.ESRCH, syscall.ENXIO} {
		if errors.Is(err, e) {
			return true
		}
	}
	text := err.Error()
	var ce *CommandError
	if errors.As(err, &ce) {
		text = ce.Output + " " + text
	}
	text = strings.ToLower(text)
	for _, sig := range absentSignatures {
		if strings.Contains(text, sig) {
			return true
		}
	}
	return false
}

func IgnoreAbsent(err error) error {
	if IsAbsent(err) {
		return nil
	}
	return err
}

func ValidPublicHost(a netip.Addr) bool {
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLoopback() {
		return false
	}
	return true
}

func IsOurRulePriority(prio int) bool {
	if prio == domain.RulePrioPublic {
		return true
	}
	for _, s := range domain.Slots() {
		if prio == s.RulePrioSrc() || prio == s.RulePrioUID() {
			return true
		}
	}
	return false
}

func IsDongleIface(name string) bool {
	_, ok := domain.ParseIfaceName(name)
	return ok
}
