package authz_test

import (
	"testing"

	"github.com/oekit/kitx/authz"
	"github.com/oekit/kitx/authz/authztest"
)

// kitx 自身的 MemSessionStore 必须通过对外发布的契约套件——下游照此运行
// 自己的 Redis 适配器即可获得同等语义保证（#196）。
func TestMemSessionStoreContract(t *testing.T) {
	authztest.Run(t, func(t *testing.T) authz.SessionStore {
		return authz.NewMemSessionStore()
	})
}
