//go:build dev

package main

import (
	"testing"

	"github.com/n4darae/huawei-API/src/internal/auth"
)

func TestTheDevSeedPasswordSatisfiesThePasswordPolicy(t *testing.T) {
	if len(devSeedPassword) < auth.MinPasswordLen {
		t.Fatalf("devSeedPassword is %d characters, the policy needs %d, so --dev-seed cannot start",
			len(devSeedPassword), auth.MinPasswordLen)
	}
}
