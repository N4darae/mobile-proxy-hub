package linux

import (
	"context"
	"errors"
	"testing"

	"github.com/n4darae/huawei-API/src/internal/netcfg"
)

func TestATruncatedDumpFailsInsteadOfReturningAPartialPicture(t *testing.T) {
	restore := dumpBufSize
	dumpBufSize = 64
	t.Cleanup(func() { dumpBufSize = restore })

	if _, err := NewObserver(nil).Links(context.Background()); !errors.Is(err, netcfg.ErrTruncatedNetlink) {
		t.Fatalf("a dump into a 64 byte buffer returned %v, want ErrTruncatedNetlink", err)
	}
}
