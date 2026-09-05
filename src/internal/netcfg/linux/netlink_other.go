//go:build !linux

package linux

import (
	"context"

	"github.com/n4darae/huawei-API/src/internal/domain"
	"github.com/n4darae/huawei-API/src/internal/netcfg"
)

func dump(context.Context, uint16, []byte) ([]nlMsg, error) {
	return nil, domain.UnsupportedOn("rtnetlink dumps")
}

func (o *Observer) Subscribe(context.Context) (<-chan netcfg.LinkEvent, func(), error) {
	return nil, nil, domain.UnsupportedOn("rtnetlink link event subscription")
}
