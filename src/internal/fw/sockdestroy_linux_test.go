package fw

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestKillSocketsReturnsZeroForAnAddressWithNoSockets(t *testing.T) {
	n := NewNft(Options{Exec: newFakeNft().exec})
	killed, err := n.KillSockets(context.Background(), netip.MustParseAddr("192.0.2.222"))
	if err != nil {
		t.Fatalf("KillSockets: %v", err)
	}
	if killed != 0 {
		t.Fatalf("want a real zero, got %d", killed)
	}
}

func TestATruncatedDiagDumpFailsInsteadOfUndercounting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer ln.Close()

	restore := dumpBufSize
	dumpBufSize = 64
	t.Cleanup(func() { dumpBufSize = restore })

	if _, err := CountEstablishedFrom(netip.MustParseAddr("127.0.0.1")); !errors.Is(err, ErrTruncatedNetlink) {
		t.Fatalf("a diag dump into a 64 byte buffer returned %v, want ErrTruncatedNetlink", err)
	}
}

func TestSocketDiagSeesALoopbackConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer server.Close()

	got, err := CountEstablishedFrom(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatalf("CountEstablishedFrom: %v", err)
	}
	if got < 2 {
		t.Fatalf("the diag dump must see both ends of a loopback connection, got %d", got)
	}
}
