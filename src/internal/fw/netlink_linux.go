package fw

import (
	"context"
	"encoding/binary"
	"fmt"
	"syscall"
	"time"
)

const (
	netlinkRecvSliceTimeout = 200 * time.Millisecond
	netlinkRecvOverallCap   = 5 * time.Second
)

var (
	dumpBufSize    = 1 << 17
	requestBufSize = 1 << 16
)

type netlinkConn struct {
	fd  int
	seq uint32
}

func dialNetlink(proto int) (*netlinkConn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	tv := syscall.NsecToTimeval(netlinkRecvSliceTimeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &netlinkConn{fd: fd}, nil
}

func (c *netlinkConn) recvfrom(ctx context.Context, buf []byte) (int, error) {
	deadline := time.Now().Add(netlinkRecvOverallCap)
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n, _, err := syscall.Recvfrom(c.fd, buf, syscall.MSG_TRUNC)
		if err == nil {
			return n, nil
		}
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			if !time.Now().Before(deadline) {
				return 0, syscall.EAGAIN
			}
			continue
		}
		return 0, err
	}
}

func (c *netlinkConn) Close() error { return syscall.Close(c.fd) }

func (c *netlinkConn) send(kind uint16, flags uint16, payload []byte) error {
	c.seq++
	msg := make([]byte, sizeofNlMsgHdr+len(payload))
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], kind)
	binary.NativeEndian.PutUint16(msg[6:8], flags)
	binary.NativeEndian.PutUint32(msg[8:12], c.seq)
	copy(msg[sizeofNlMsgHdr:], payload)
	return syscall.Sendto(c.fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}

func (c *netlinkConn) dump(ctx context.Context, kind uint16, payload []byte) ([][]byte, error) {
	if err := c.send(kind, nlmFRequest|nlmFDump, payload); err != nil {
		return nil, err
	}
	var out [][]byte
	for {
		buf := make([]byte, dumpBufSize)
		n, err := c.recvfrom(ctx, buf)
		if err != nil {
			return nil, err
		}
		if n > len(buf) {
			return nil, fmt.Errorf("%w: %d bytes into %d", ErrTruncatedNetlink, n, len(buf))
		}
		if n < sizeofNlMsgHdr {
			return nil, ErrMalformedNetlink
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
				if err := decodeNetlinkError(m.Data); err != nil {
					return nil, err
				}
				done = true
			default:
				out = append(out, m.Data)
			}
		}
		if done {
			break
		}
	}
	return out, nil
}

func (c *netlinkConn) request(ctx context.Context, kind uint16, payload []byte) error {
	if err := c.send(kind, nlmFRequest|nlmFAck, payload); err != nil {
		return err
	}
	for {
		buf := make([]byte, requestBufSize)
		n, err := c.recvfrom(ctx, buf)
		if err != nil {
			return err
		}
		if n > len(buf) {
			return fmt.Errorf("%w: %d bytes into %d", ErrTruncatedNetlink, n, len(buf))
		}
		if n < sizeofNlMsgHdr {
			return ErrMalformedNetlink
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case nlmsgError:
				return decodeNetlinkError(m.Data)
			case nlmsgDone:
				return nil
			}
		}
	}
}

func decodeNetlinkError(data []byte) error {
	if len(data) < 4 {
		return ErrMalformedNetlink
	}
	code := int32(binary.NativeEndian.Uint32(data[0:4]))
	if code == 0 {
		return nil
	}
	return syscall.Errno(-code)
}
