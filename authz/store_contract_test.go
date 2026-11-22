package authz_test

import (
	"testing"
	"time"

	"github.com/oekit/authx/authz"
	"github.com/oekit/authx/authz/authztest"
)

// kitx 自身的 MemSessionStore 必须通过对外发布的契约套件——下游照此运行
// 自己的 Redis 适配器即可获得同等语义保证（#196）。
func TestMemSessionStoreContract(t *testing.T) {
	authztest.Run(t, func(t *testing.T) authz.SessionStore {
		return authz.NewMemSessionStore()
	})
}

// TestMemSessionStoreNilCtx 钉住 MemSessionStore 全部 8 个入口对 nil ctx 的
// 兜底（#231）：按 Background 语义工作，不得 nil 解引用 panic。契约套件的
// RunRegistry 传给 store 的是归一后的 ctx，盖不到「直调 store 传 nil」的路径，
// 故在此直测参考实现自身。
func TestMemSessionStoreNilCtx(t *testing.T) {
	store := authz.NewMemSessionStore()

	//nolint:staticcheck // SA1012：传 nil ctx 正是本测试点
	if ok, err := store.SetNX(nil, "k", "v", time.Hour); err != nil || !ok {
		t.Fatalf("SetNX(nil) = (%v, %v), want (true, nil)", ok, err)
	}
	//nolint:staticcheck // SA1012：传 nil ctx 正是本测试点
	if v, ok, err := store.Get(nil, "k"); err != nil || !ok || v != "v" {
		t.Fatalf("Get(nil) = (%q, %v, %v), want (\"v\", true, nil)", v, ok, err)
	}
	//nolint:staticcheck // SA1012：传 nil ctx 正是本测试点
	if err := store.SAdd(nil, "set", "m1", time.Hour); err != nil {
		t.Fatalf("SAdd(nil) error = %v", err)
	}
	//nolint:staticcheck // SA1012：传 nil ctx 正是本测试点
	if members, err := store.SMembers(nil, "set"); err != nil || len(members) != 1 || members[0] != "m1" {
		t.Fatalf("SMembers(nil) = (%v, %v), want [m1]", members, err)
	}
	//nolint:staticcheck // SA1012：传 nil ctx 正是本测试点
	if remaining, ok, err := store.TTL(nil, "k"); err != nil || !ok || remaining <= 0 {
		t.Fatalf("TTL(nil) = (%v, %v, %v), want 正剩余寿命", remaining, ok, err)
	}
	//nolint:staticcheck // SA1012：传 nil ctx 正是本测试点
	if ok, err := store.Expire(nil, "k", time.Hour); err != nil || !ok {
		t.Fatalf("Expire(nil) = (%v, %v), want (true, nil)", ok, err)
	}
	//nolint:staticcheck // SA1012：传 nil ctx 正是本测试点
	if err := store.SRem(nil, "set", "m1"); err != nil {
		t.Fatalf("SRem(nil) error = %v", err)
	}
	//nolint:staticcheck // SA1012：传 nil ctx 正是本测试点
	if ok, err := store.Del(nil, "k"); err != nil || !ok {
		t.Fatalf("Del(nil) = (%v, %v), want (true, nil)", ok, err)
	}
}
