package fw

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	netlinkInetDiag = 4
	netlinkNetfil   = 12

	sockDiagByFamily = 20
	sockDestroy      = 21

	sizeofSockID   = 48
	sizeofDiagReq  = 8 + sizeofSockID
	sizeofDiagMsg  = 4 + sizeofSockID + 20
	sizeofNlMsgHdr = 16

	nlmsgError = 0x2
	nlmsgDone  = 0x3

	nlmFRequest = 0x001
	nlmFAck     = 0x004
	nlmFDump    = 0x300

	afInet   = 2
	afInet6  = 10
	protoTCP = 6

	tcpEstablished = 1
	tcpListen      = 10
	tcpMaxStates   = 13
)

var ErrMalformedNetlink = errors.New("fw: malformed netlink message")

var ErrTruncatedNetlink = errors.New("fw: netlink datagram did not fit the receive buffer")

func killableStates() uint32 {
	var mask uint32
	for s := 1; s < tcpMaxStates; s++ {
		if s == tcpListen {
			continue
		}
		mask |= 1 << uint(s)
	}
	return mask
}

type inetDiagEntry struct {
	Family uint8
	State  uint8
	Src    netip.Addr
	Dst    netip.Addr
	SPort  uint16
	DPort  uint16
	UID    uint32
	Inode  uint32
	ID     []byte
}

func encodeDiagReq(family, protocol uint8, states uint32, id []byte) []byte {
	req := make([]byte, sizeofDiagReq)
	req[0] = family
	req[1] = protocol
	binary.NativeEndian.PutUint32(req[4:8], states)
	if len(id) == sizeofSockID {
		copy(req[8:], id)
	}
	return req
}

func parseDiagMsg(data []byte) (inetDiagEntry, bool) {
	if len(data) < sizeofDiagMsg {
		return inetDiagEntry{}, false
	}
	e := inetDiagEntry{Family: data[0], State: data[1]}
	id := data[4 : 4+sizeofSockID]
	e.ID = append([]byte(nil), id...)
	e.SPort = binary.BigEndian.Uint16(id[0:2])
	e.DPort = binary.BigEndian.Uint16(id[2:4])
	switch e.Family {
	case afInet:
		e.Src = netip.AddrFrom4([4]byte(id[4:8]))
		e.Dst = netip.AddrFrom4([4]byte(id[20:24]))
	case afInet6:
		e.Src = netip.AddrFrom16([16]byte(id[4:20])).Unmap()
		e.Dst = netip.AddrFrom16([16]byte(id[20:36])).Unmap()
	default:
		return inetDiagEntry{}, false
	}
	e.UID = binary.NativeEndian.Uint32(data[4+sizeofSockID+12 : 4+sizeofSockID+16])
	e.Inode = binary.NativeEndian.Uint32(data[4+sizeofSockID+16 : 4+sizeofSockID+20])
	return e, true
}

func familyOf(a netip.Addr) uint8 {
	if a.Is4() {
		return afInet
	}
	return afInet6
}

func listSockets(ctx context.Context, family uint8, states uint32) ([]inetDiagEntry, error) {
	c, err := dialNetlink(netlinkInetDiag)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	payloads, err := c.dump(ctx, sockDiagByFamily, encodeDiagReq(family, protoTCP, states, nil))
	if err != nil {
		return nil, err
	}
	out := make([]inetDiagEntry, 0, len(payloads))
	for _, p := range payloads {
		if e, ok := parseDiagMsg(p); ok {
			out = append(out, e)
		}
	}
	return out, nil
}

func socketsFrom(ctx context.Context, src netip.Addr) ([]inetDiagEntry, error) {
	if !src.IsValid() {
		return nil, ErrBadAddr
	}
	all, err := listSockets(ctx, familyOf(src), killableStates())
	if err != nil {
		return nil, err
	}
	var out []inetDiagEntry
	for _, e := range all {
		if e.Src == src {
			out = append(out, e)
		}
	}
	return out, nil
}

func SocketsFrom(src netip.Addr) ([]inetDiagEntry, error) {
	return socketsFrom(context.Background(), src)
}

func HasListener(addr netip.Addr, port int) (bool, error) {
	if !addr.IsValid() {
		return false, ErrBadAddr
	}
	entries, err := listSockets(context.Background(), familyOf(addr), 1<<tcpListen)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if int(e.SPort) != port {
			continue
		}
		if e.Src == addr || e.Src.IsUnspecified() {
			return true, nil
		}
	}
	return false, nil
}

func CountEstablishedFrom(src netip.Addr) (int, error) {
	socks, err := SocketsFrom(src)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range socks {
		if s.State == tcpEstablished {
			n++
		}
	}
	return n, nil
}

func (n *Nft) KillSockets(ctx context.Context, src netip.Addr) (int, error) {
	if !src.IsValid() {
		return 0, ErrBadAddr
	}
	targets, err := socketsFrom(ctx, src)
	if err != nil {
		return 0, err
	}
	if len(targets) == 0 {
		return 0, nil
	}
	c, err := dialNetlink(netlinkInetDiag)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	killed := 0
	for _, t := range targets {
		if ctx.Err() != nil {
			return killed, ctx.Err()
		}
		req := encodeDiagReq(t.Family, protoTCP, 0, t.ID)
		if err := c.request(ctx, sockDestroy, req); err != nil {
			continue
		}
		killed++
	}
	return killed, nil
}
