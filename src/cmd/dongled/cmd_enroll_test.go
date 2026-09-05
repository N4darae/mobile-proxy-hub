package main

import (
	"testing"

	"github.com/n4darae/huawei-API/src/internal/config"
)

func TestTheFarmMarkerFollowsTheConfiguredEtcDir(t *testing.T) {
	cfg := config.Config{EtcDir: "/srv/scratch/etc"}
	if got := cfg.FarmMarkerPath(); got != "/srv/scratch/etc/FARM" {
		t.Fatalf("FarmMarkerPath is %q, want it under the configured etc dir", got)
	}
	if got := (config.Config{}).FarmMarkerPath(); got != config.FarmMarker {
		t.Fatalf("an unset etc dir gave %q, want the packaged default %q", got, config.FarmMarker)
	}
}
