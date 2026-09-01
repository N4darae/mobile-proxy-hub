package linux

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/n4darae/huawei-API/src/internal/netcfg"
)

const (
	netlinkRecvSliceTimeout = 200 * time.Millisecond
	netlinkRecvOverallCap   = 5 * time.Second
)

func dump(ctx context.Context, proto uint16, payload []byte) ([]nlMsg, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	lsa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, lsa); err != nil {
		return nil, err
	}
	tv := syscall.NsecToTimeval(netlinkRecvSliceTimeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}
	req := make([]byte, sizeofNlMsgHdr+len(payload))
	binary.NativeEndian.PutUint32(req[0:4], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:6], proto)
	binary.NativeEndian.PutUint16(req[6:8], nlmFRequest|nlmFDump)
	binary.NativeEndian.PutUint32(req[8:12], 1)
	copy(req[sizeofNlMsgHdr:], payload)
	if err := syscall.Sendto(fd, req, 0, lsa); err != nil {
		return nil, err
	}
	var out []nlMsg
	for {
		buf := make([]byte, 1<<17)
		n, err := recvfrom(ctx, fd, buf)
		if err != nil {
			return nil, err
		}
		if n < sizeofNlMsgHdr {
			return nil, netcfg.ErrMalformedNetlink
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		done := false
		for _, m := range msgs {
			switch m.Header.Type {
			case nlmsgDone:
				done = true
			case nlmsgError:
				return nil, netlinkError(m.Data)
			default:
				out = append(out, nlMsg{Header: nlMsgHdr(m.Header), Data: m.Data})
			}
		}
		if done {
			break
		}
	}
	return out, nil
}

func recvfrom(ctx context.Context, fd int, buf []byte) (int, error) {
	deadline := time.Now().Add(netlinkRecvOverallCap)
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err == nil {
			return n, nil
		}
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
			if !time.Now().Before(deadline) {
				return 0, syscall.EAGAIN
			}
			continue
		}
		return 0, err
	}
}

func netlinkError(data []byte) error {
	if len(data) < 4 {
		return netcfg.ErrMalformedNetlink
	}
	code := int32(binary.NativeEndian.Uint32(data[0:4]))
	if code == 0 {
		return nil
	}
	return syscall.Errno(-code)
}

type subscription struct {
	fd      int
	ch      chan netcfg.LinkEvent
	stopped atomic.Bool
}

func (o *Observer) Subscribe(ctx context.Context) (<-chan netcfg.LinkEvent, func(), error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, nil, err
	}
	lsa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: rtnlGroupLink}
	if err := syscall.Bind(fd, lsa); err != nil {
		syscall.Close(fd)
		return nil, nil, err
	}
	tv := syscall.Timeval{Sec: 0, Usec: 400000}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return nil, nil, err
	}
	s := &subscription{fd: fd, ch: make(chan netcfg.LinkEvent, 64)}
	var closeOnce sync.Once
	closeFD := func() { closeOnce.Do(func() { syscall.Close(fd) }) }
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.stopped.Store(true)
			closeFD()
		case <-done:
		}
	}()
	go func() {
		defer close(done)
		defer close(s.ch)
		defer closeFD()
		seen := map[int]struct{}{}
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if s.stopped.Load() {
				return
			}
			buf := make([]byte, 1<<16)
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
					continue
				}
				return
			}
			msgs, err := syscall.ParseNetlinkMessage(buf[:n])
			if err != nil {
				continue
			}
			for _, m := range msgs {
				ev, ok := decodeLinkEvent(nlMsg{Header: nlMsgHdr(m.Header), Data: m.Data}, seen)
				if !ok {
					continue
				}
				select {
				case s.ch <- ev:
				default:
				}
			}
		}
	}()
	return s.ch, func() { s.stopped.Store(true) }, nil
}
