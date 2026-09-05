//go:build dev

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/n4darae/huawei-API/src/internal/auth"
	"github.com/n4darae/huawei-API/src/internal/config"
)

const (
	devSeedUser     = "admin"
	devSeedPassword = "admin-dev"
)

func seedDevAdmin(ctx context.Context, cfg config.Config, sessions *auth.Sessions) error {
	if !cfg.DevSeed {
		return nil
	}
	if err := sessions.SetPassword(ctx, devSeedUser, devSeedPassword); err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, devSeedBanner)
	return nil
}

const devSeedBanner = `
################################################################################
#  DEVELOPMENT SEED IS ACTIVE                                                  #
#                                                                              #
#  A panel account admin / admin-dev now exists and anyone who can reach this  #
#  listener owns the whole farm: every proxy password, every customer, every   #
#  SIM. This build carries the "dev" tag; never run it on the farm host and    #
#  never expose this listener beyond 127.0.0.1.                                #
#                                                                              #
#  Set a real password with: dongled passwd admin                              #
################################################################################

`
