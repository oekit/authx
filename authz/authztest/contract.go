// Package authztest 提供 authz.SessionStore 的契约测试套件（#196）：下游把
// 自己的 Redis 等持久存储适配器塞进 Run，同一组用例验证「键值/集合原语语义 +
// kitx 编排层依赖的会话注册表行为」。
//
// 套件分两层：
//
//   - RunStore：SessionStore 原语契约（Get/SetNX/Del/SAdd/SRem/SMembers/
//     Expire/TTL 的返回值、TTL 语义、SetNX 原子性、集合 TTL 只延长不缩短）；
//   - RunRegistry：基于 authz.NewStoreRegistry 的编排契约（重复 ID/refreshHash
//     唯一挂载/Kick 三态/KickUser 聚合计数）。
//
// 用法（下游 store 实现）：
//
//	func TestRedisStoreContract(t *testing.T) {
//	    authztest.Run(t, func(t *testing.T) authz.SessionStore {
//	        return newRedisStore(t) // 每次返回隔离命名空间的空 store
//	    })
//	}
//
// 工厂约定：每次调用返回**空且互不冲突**的 store（独立前缀/独立 DB）；套件
// 自身也会为每个用例生成唯一键前缀，但 store 契约测试（SetNX/TTL）要求键空间
// 可写且无残留。TTL 用例使用短寿命 + 轮询（最长数秒），适配真实 Redis。
package authztest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oekit/kitx/authz"
	bizerrors "github.com/oekit/pkg/errors"
)

// StoreFactory 返回一份隔离的 SessionStore（每次调用都应是空命名空间）。
type StoreFactory func(t *testing.T) authz.SessionStore

// Run 跑完整契约：原语语义 + 编排行为。
func Run(t *testing.T, newStore StoreFactory) {
	t.Helper()
	t.Run("Store", func(t *testing.T) { RunStore(t, newStore) })
	t.Run("Registry", func(t *testing.T) { RunRegistry(t, newStore) })
}

// RunStore 只跑 SessionStore 原语契约。
func RunStore(t *testing.T, newStore StoreFactory) {
	t.Helper()
	ctx := context.Background()
	store := newStore(t)
	if store == nil {
		t.Fatal("StoreFactory 返回 nil SessionStore")
	}

	t.Run("GetMissing", func(t *testing.T) {
		v, ok, err := store.Get(ctx, key(t, "missing"))
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if ok || v != "" {
			t.Fatalf("Get() = (%q, %v), want (\"\", false)", v, ok)
		}
	})

	t.Run("SetNXIsAtomic", func(t *testing.T) {
		k := key(t, "setnx")
		ok, err := store.SetNX(ctx, k, "first", time.Hour)
		if err != nil || !ok {
			t.Fatalf("首次 SetNX = (%v, %v), want (true, nil)", ok, err)
		}
		ok, err = store.SetNX(ctx, k, "second", time.Hour)
		if err != nil {
			t.Fatalf("二次 SetNX error = %v", err)
		}
		if ok {
			t.Fatal("已存在的键 SetNX 必须返回 false（不得覆盖）")
		}
		v, exists, err := store.Get(ctx, k)
		if err != nil || !exists || v != "first" {
			t.Fatalf("Get() = (%q, %v, %v), want (\"first\", true, nil)", v, exists, err)
		}
	})

	t.Run("SetNXConcurrentClaim", func(t *testing.T) {
		k := key(t, "setnx-race")
		const n = 8
		start := make(chan struct{})
		wins := make(chan bool, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				ok, err := store.SetNX(ctx, k, fmt.Sprintf("v%d", i), time.Hour)
				if err != nil {
					t.Errorf("SetNX(%d) error = %v", i, err)
					return
				}
				wins <- ok
			}(i)
		}
		close(start)
		wg.Wait()
		close(wins)
		got := 0
		for ok := range wins {
			if ok {
				got++
			}
		}
		if got != 1 {
			t.Fatalf("并发 SetNX 必须恰一胜（%d/%d）——原子性是多实例强踢拍板的前提", got, n)
		}
	})

	t.Run("SetNXRequiresPositiveTTL", func(t *testing.T) {
		for _, ttl := range []time.Duration{0, -time.Second} {
			if _, err := store.SetNX(ctx, key(t, "bad-ttl"), "v", ttl); err == nil {
				t.Fatalf("SetNX ttl=%v 必须报错（禁止无过期键）", ttl)
			}
		}
	})

	t.Run("SetNXTTLExpiry", func(t *testing.T) {
		k := key(t, "ttl")
		ok, err := store.SetNX(ctx, k, "v", 500*time.Millisecond)
		if err != nil || !ok {
			t.Fatalf("SetNX = (%v, %v), want (true, nil)", ok, err)
		}
		remaining, exists, err := store.TTL(ctx, k)
		if err != nil {
			t.Fatalf("TTL() error = %v", err)
		}
		if !exists || remaining <= 0 || remaining > time.Minute {
			t.Fatalf("TTL = (%v, %v), want 正剩余寿命", remaining, exists)
		}
		waitGone(t, store, k)
	})

	t.Run("Del", func(t *testing.T) {
		k := key(t, "del")
		if _, err := store.SetNX(ctx, k, "v", time.Hour); err != nil {
			t.Fatal(err)
		}
		ok, err := store.Del(ctx, k)
		if err != nil || !ok {
			t.Fatalf("Del(existing) = (%v, %v), want (true, nil)", ok, err)
		}
		ok, err = store.Del(ctx, k)
		if err != nil || ok {
			t.Fatalf("Del(missing) = (%v, %v), want (false, nil)", ok, err)
		}
		if _, exists, _ := store.Get(ctx, k); exists {
			t.Fatal("Del 后 Get 必须不存在")
		}
	})

	t.Run("TTLMissing", func(t *testing.T) {
		if _, exists, err := store.TTL(ctx, key(t, "ttl-missing")); err != nil || exists {
			t.Fatalf("TTL(missing) = (_, %v, %v), want exists=false", exists, err)
		}
	})

	t.Run("Expire", func(t *testing.T) {
		k := key(t, "expire")
		if _, err := store.SetNX(ctx, k, "v", time.Hour); err != nil {
			t.Fatal(err)
		}
		ok, err := store.Expire(ctx, k, 500*time.Millisecond)
		if err != nil || !ok {
			t.Fatalf("Expire(existing) = (%v, %v), want (true, nil)", ok, err)
		}
		waitGone(t, store, k)
		ok, err = store.Expire(ctx, k, time.Hour)
		if err != nil || ok {
			t.Fatalf("Expire(missing) = (%v, %v), want (false, nil)", ok, err)
		}
		if _, err := store.Expire(ctx, key(t, "expire-bad"), 0); err == nil {
			t.Fatal("Expire ttl=0 必须报错")
		}
	})

	t.Run("DelSet", func(t *testing.T) {
		k := key(t, "del-set")
		if err := store.SAdd(ctx, k, "m1", time.Hour); err != nil {
			t.Fatal(err)
		}
		ok, err := store.Del(ctx, k)
		if err != nil || !ok {
			t.Fatalf("Del(set) = (%v, %v), want (true, nil)", ok, err)
		}
		if members, err := store.SMembers(ctx, k); err != nil || len(members) != 0 {
			t.Fatalf("Del(set) 后 SMembers = (%v, %v), want 空集", members, err)
		}
	})

	t.Run("SetMembers", func(t *testing.T) {
		k := key(t, "set")
		if err := store.SAdd(ctx, k, "m1", time.Hour); err != nil {
			t.Fatalf("SAdd(m1) error = %v", err)
		}
		if err := store.SAdd(ctx, k, "m2", time.Hour); err != nil {
			t.Fatalf("SAdd(m2) error = %v", err)
		}
		members, err := store.SMembers(ctx, k)
		if err != nil {
			t.Fatalf("SMembers() error = %v", err)
		}
		sort.Strings(members)
		if len(members) != 2 || members[0] != "m1" || members[1] != "m2" {
			t.Fatalf("SMembers = %v, want [m1 m2]", members)
		}
		if err := store.SRem(ctx, k, "m1"); err != nil {
			t.Fatalf("SRem(m1) error = %v", err)
		}
		if err := store.SRem(ctx, k, "missing"); err != nil {
			t.Fatalf("SRem(missing) 必须幂等，error = %v", err)
		}
		members, _ = store.SMembers(ctx, k)
		if len(members) != 1 || members[0] != "m2" {
			t.Fatalf("SRem 后 SMembers = %v, want [m2]", members)
		}
		if members, err := store.SMembers(ctx, key(t, "set-missing")); err != nil || len(members) != 0 {
			t.Fatalf("SMembers(missing) = (%v, %v), want 空集", members, err)
		}
		if err := store.SAdd(ctx, key(t, "set-bad"), "m", 0); err == nil {
			t.Fatal("SAdd ttl=0 必须报错")
		}
	})

	t.Run("SetTTLNeverShortens", func(t *testing.T) {
		k := key(t, "set-ttl")
		if err := store.SAdd(ctx, k, "m1", 2*time.Hour); err != nil {
			t.Fatal(err)
		}
		remaining, exists, err := store.TTL(ctx, k)
		if err != nil || !exists || remaining < time.Hour {
			t.Fatalf("首次 SAdd 后 TTL = (%v, %v, %v), want ≥1h", remaining, exists, err)
		}
		if err := store.SAdd(ctx, k, "m2", 10*time.Minute); err != nil {
			t.Fatal(err)
		}
		remaining, exists, err = store.TTL(ctx, k)
		if err != nil || !exists || remaining < time.Hour {
			t.Fatalf("短 TTL SAdd 不得缩短集合寿命：TTL = (%v, %v, %v)", remaining, exists, err)
		}
		if err := store.SAdd(ctx, k, "m3", 4*time.Hour); err != nil {
			t.Fatal(err)
		}
		remaining, exists, err = store.TTL(ctx, k)
		if err != nil || !exists || remaining < 3*time.Hour {
			t.Fatalf("长 TTL SAdd 必须延长集合寿命：TTL = (%v, %v, %v)", remaining, exists, err)
		}
	})
}

// RunRegistry 跑基于 authz.NewStoreRegistry 的编排契约（下游 store 的最终验收面）。
func RunRegistry(t *testing.T, newStore StoreFactory) {
	t.Helper()
	ctx := context.Background()

	newRegistry := func(t *testing.T) (*authz.StoreRegistry, *authz.MemRevoker) {
		t.Helper()
		rev := authz.NewMemRevoker()
		store := newStore(t)
		if store == nil {
			t.Fatal("StoreFactory 返回 nil SessionStore")
		}
		reg, err := authz.NewStoreRegistry(rev, store, authz.WithStorePrefix(prefix(t)))
		if err != nil {
			t.Fatalf("NewStoreRegistry() error = %v", err)
		}
		return reg, rev
	}

	t.Run("RegisterValidation", func(t *testing.T) {
		reg, _ := newRegistry(t)
		bad := map[string]authz.Session{
			"missing ID":          {UserID: "u-1", RefreshHash: authz.TokenHash("r-1")},
			"missing UserID":      {ID: "s-1", RefreshHash: authz.TokenHash("r-1")},
			"missing RefreshHash": {ID: "s-1", UserID: "u-1"},
		}
		for name, s := range bad {
			if err := reg.Register(ctx, s, time.Hour); err == nil {
				t.Fatalf("[%s] Register 必须报错", name)
			}
		}
		s := session("s-1", "u-1", "r-1")
		if err := reg.Register(ctx, s, 0); err == nil {
			t.Fatal("ttl=0 必须报错——零值透传等于登记长生会话")
		}
		if err := reg.Register(ctx, s, -time.Hour); err == nil {
			t.Fatal("负 ttl 必须报错")
		}
		if err := reg.Register(ctx, s, time.Hour); err != nil {
			t.Fatalf("Register() error = %v", err)
		}
	})

	t.Run("DuplicateIDRejected", func(t *testing.T) {
		reg, _ := newRegistry(t)
		if err := reg.Register(ctx, session("s-1", "u-1", "r-1"), time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := reg.Register(ctx, session("s-1", "u-1", "r-2"), time.Hour); err == nil {
			t.Fatal("重复会话 ID 注册必须报错（登记不可覆盖）")
		}
	})

	t.Run("RefreshHashAlreadyMounted", func(t *testing.T) {
		reg, _ := newRegistry(t)
		if err := reg.Register(ctx, session("s-1", "u-1", "r-1"), time.Hour); err != nil {
			t.Fatal(err)
		}
		// 同一 refresh 挂第二枚会话（不同 ID）必须报错——登记面也是防重放面。
		if err := reg.Register(ctx, session("s-2", "u-1", "r-1"), time.Hour); err == nil {
			t.Fatal("refreshHash 已挂载必须报错")
		}
	})

	t.Run("GetByRefreshHash", func(t *testing.T) {
		reg, _ := newRegistry(t)
		s := session("s-1", "u-1", "r-1")
		if err := reg.Register(ctx, s, time.Hour); err != nil {
			t.Fatal(err)
		}
		got, err := reg.GetByRefreshHash(ctx, s.RefreshHash)
		if err != nil {
			t.Fatalf("GetByRefreshHash() error = %v", err)
		}
		if got.ID != s.ID || got.UserID != s.UserID || got.Device != s.Device {
			t.Fatalf("GetByRefreshHash = %+v, want %+v", got, s)
		}
		if _, err := reg.GetByRefreshHash(ctx, authz.TokenHash("r-missing")); !errors.Is(err, authz.ErrSessionNotFound) {
			t.Fatalf("未登记 refresh error = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("ListByUser", func(t *testing.T) {
		reg, _ := newRegistry(t)
		s1 := session("s-1", "u-1", "r-1")
		s2 := session("s-2", "u-1", "r-2")
		s2.LoginAt = s1.LoginAt.Add(time.Minute)
		s3 := session("s-3", "u-2", "r-3")
		for _, s := range []authz.Session{s1, s2, s3} {
			if err := reg.Register(ctx, s, time.Hour); err != nil {
				t.Fatalf("Register(%s) error = %v", s.ID, err)
			}
		}
		list, err := reg.ListByUser(ctx, "u-1")
		if err != nil {
			t.Fatalf("ListByUser() error = %v", err)
		}
		if len(list) != 2 || list[0].ID != "s-1" || list[1].ID != "s-2" {
			t.Fatalf("ListByUser(u-1) = %v, want [s-1 s-2]（LoginAt 升序）", ids(list))
		}
		if list, _ := reg.ListByUser(ctx, "u-2"); len(list) != 1 || list[0].ID != "s-3" {
			t.Fatalf("ListByUser(u-2) = %v, want [s-3]", ids(list))
		}
		if list, _ := reg.ListByUser(ctx, "u-missing"); len(list) != 0 {
			t.Fatalf("无会话用户应为空列表，got %v", ids(list))
		}
	})

	t.Run("KickNotFound", func(t *testing.T) {
		reg, _ := newRegistry(t)
		kicked, err := reg.Kick(ctx, "s-missing")
		if err != nil || kicked {
			t.Fatalf("Kick(missing) = (%v, %v), want (false, nil)——幂等强踢的常态", kicked, err)
		}
	})

	t.Run("KickRevokesAndDeletes", func(t *testing.T) {
		reg, rev := newRegistry(t)
		s := session("s-1", "u-1", "r-1")
		if err := reg.Register(ctx, s, time.Hour); err != nil {
			t.Fatal(err)
		}
		kicked, err := reg.Kick(ctx, s.ID)
		if err != nil || !kicked {
			t.Fatalf("Kick = (%v, %v), want (true, nil)", kicked, err)
		}
		for name, hash := range map[string]string{"access": s.AccessHash, "refresh": s.RefreshHash} {
			if hit, err := rev.Revoked(ctx, hash); err != nil || !hit {
				t.Fatalf("Kick 后 %s hash 必须已拉黑（hit=%v err=%v）", name, hit, err)
			}
		}
		if _, err := reg.GetByRefreshHash(ctx, s.RefreshHash); !errors.Is(err, authz.ErrSessionNotFound) {
			t.Fatalf("Kick 后会话必须已删键，error = %v", err)
		}
		if list, _ := reg.ListByUser(ctx, s.UserID); len(list) != 0 {
			t.Fatalf("Kick 后用户列表必须为空，got %v", ids(list))
		}
		if kicked, err := reg.Kick(ctx, s.ID); err != nil || kicked {
			t.Fatalf("二次 Kick = (%v, %v), want (false, nil)", kicked, err)
		}
	})

	t.Run("KickEmptyAccessHash", func(t *testing.T) {
		reg, rev := newRegistry(t)
		s := session("s-1", "u-1", "r-1")
		s.AccessHash = ""
		if err := reg.Register(ctx, s, time.Hour); err != nil {
			t.Fatal(err)
		}
		kicked, err := reg.Kick(ctx, s.ID)
		if err != nil || !kicked {
			t.Fatalf("Kick = (%v, %v), want (true, nil)", kicked, err)
		}
		if hit, _ := rev.Revoked(ctx, s.RefreshHash); !hit {
			t.Fatal("空 access hash 不得影响 refresh 拉黑路")
		}
	})

	t.Run("KickExpiredSession", func(t *testing.T) {
		reg, _ := newRegistry(t)
		s := session("s-1", "u-1", "r-1")
		if err := reg.Register(ctx, s, 100*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		waitSessionGone(t, reg, s.RefreshHash)
		if kicked, err := reg.Kick(ctx, s.ID); err != nil || kicked {
			t.Fatalf("过期会话 Kick = (%v, %v), want (false, nil)", kicked, err)
		}
	})

	t.Run("KickRevokeFailureRetainsRegistration", func(t *testing.T) {
		rev := &failingRevoker{inner: authz.NewMemRevoker(), fail: map[string]bool{}}
		store := newStore(t)
		reg, err := authz.NewStoreRegistry(rev, store, authz.WithStorePrefix(prefix(t)))
		if err != nil {
			t.Fatalf("NewStoreRegistry() error = %v", err)
		}
		s := session("s-1", "u-1", "r-1")
		if err := reg.Register(ctx, s, time.Hour); err != nil {
			t.Fatal(err)
		}
		rev.fail[s.RefreshHash] = true
		if kicked, err := reg.Kick(ctx, s.ID); err == nil || kicked {
			t.Fatalf("拉黑失败时 Kick = (%v, %v), want (false, err)", kicked, err)
		}
		if _, err := reg.GetByRefreshHash(ctx, s.RefreshHash); err != nil {
			t.Fatalf("拉黑失败后登记必须保留（可重试），error = %v", err)
		}
		rev.unfail(s.RefreshHash)
		if kicked, err := reg.Kick(ctx, s.ID); err != nil || !kicked {
			t.Fatalf("修复存储后重试 Kick = (%v, %v), want (true, nil)", kicked, err)
		}
	})

	t.Run("KickUser", func(t *testing.T) {
		reg, rev := newRegistry(t)
		hashes := map[string]bool{}
		for _, id := range []string{"s-1", "s-2", "s-3"} {
			s := session(id, "u-1", "r-"+id)
			if err := reg.Register(ctx, s, time.Hour); err != nil {
				t.Fatal(err)
			}
			hashes[s.AccessHash] = true
			hashes[s.RefreshHash] = true
		}
		other := session("s-4", "u-2", "r-4")
		if err := reg.Register(ctx, other, time.Hour); err != nil {
			t.Fatal(err)
		}
		n, err := reg.KickUser(ctx, "u-1")
		if err != nil {
			t.Fatalf("KickUser() error = %v", err)
		}
		if n != 3 {
			t.Fatalf("KickUser = %d, want 3", n)
		}
		for h := range hashes {
			if hit, _ := rev.Revoked(ctx, h); !hit {
				t.Fatalf("hash %s 必须已拉黑", h)
			}
		}
		if list, _ := reg.ListByUser(ctx, "u-1"); len(list) != 0 {
			t.Fatalf("u-1 会话残留 %v", ids(list))
		}
		if list, _ := reg.ListByUser(ctx, "u-2"); len(list) != 1 || list[0].ID != "s-4" {
			t.Fatalf("u-2 不得被波及，got %v", ids(list))
		}
		if n, err := reg.KickUser(ctx, "u-1"); err != nil || n != 0 {
			t.Fatalf("二次 KickUser = (%d, %v), want (0, nil)", n, err)
		}
		if n, err := reg.KickUser(ctx, "u-missing"); err != nil || n != 0 {
			t.Fatalf("无会话 KickUser = (%d, %v), want (0, nil)", n, err)
		}
	})

	t.Run("KickUserPartialFailure", func(t *testing.T) {
		rev := &failingRevoker{inner: authz.NewMemRevoker(), fail: map[string]bool{}}
		store := newStore(t)
		reg, err := authz.NewStoreRegistry(rev, store, authz.WithStorePrefix(prefix(t)))
		if err != nil {
			t.Fatalf("NewStoreRegistry() error = %v", err)
		}
		s1 := session("s-1", "u-1", "r-1")
		s2 := session("s-2", "u-1", "r-2")
		for _, s := range []authz.Session{s1, s2} {
			if err := reg.Register(ctx, s, time.Hour); err != nil {
				t.Fatal(err)
			}
		}
		rev.fail[s1.AccessHash] = true
		n, err := reg.KickUser(ctx, "u-1")
		if err == nil {
			t.Fatal("部分失败必须报错（errors.Join 聚合）")
		}
		if n != 1 {
			t.Fatalf("KickUser = %d, want 1（失败会话不计数）", n)
		}
		if _, err := reg.GetByRefreshHash(ctx, s1.RefreshHash); err != nil {
			t.Fatalf("失败会话必须保留可重试，error = %v", err)
		}
		if _, err := reg.GetByRefreshHash(ctx, s2.RefreshHash); !errors.Is(err, authz.ErrSessionNotFound) {
			t.Fatalf("成功会话必须已下线，error = %v", err)
		}
	})

	t.Run("KickAtomicClaim", func(t *testing.T) {
		reg, _ := newRegistry(t)
		s := session("s-1", "u-1", "r-1")
		if err := reg.Register(ctx, s, time.Hour); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		results := make(chan bool, 2)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				kicked, err := reg.Kick(ctx, s.ID)
				if err != nil {
					t.Errorf("Kick() error = %v", err)
				}
				results <- kicked
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		wins := 0
		for kicked := range results {
			if kicked {
				wins++
			}
		}
		if wins != 1 {
			t.Fatalf("原子认领必须恰一胜（%d/2）——防重放拍板不靠时序运气", wins)
		}
	})
}

// failingRevoker 可注入拉黑失败（契约：失败时登记保留、可重试）。
type failingRevoker struct {
	inner authz.Revoker
	mu    sync.Mutex
	fail  map[string]bool
}

func (f *failingRevoker) Revoke(ctx context.Context, hash string, remaining time.Duration) error {
	f.mu.Lock()
	bad := f.fail[hash]
	f.mu.Unlock()
	if bad {
		return bizerrors.Newf("存储故障(%s)", hash)
	}
	return f.inner.Revoke(ctx, hash, remaining)
}

func (f *failingRevoker) Revoked(ctx context.Context, hash string) (bool, error) {
	return f.inner.Revoked(ctx, hash)
}

func (f *failingRevoker) RevokeUser(ctx context.Context, userID string, at time.Time) error {
	return f.inner.RevokeUser(ctx, userID, at)
}

func (f *failingRevoker) RevokedUser(ctx context.Context, userID string, iat time.Time) (bool, error) {
	return f.inner.RevokedUser(ctx, userID, iat)
}

func (f *failingRevoker) unfail(hash string) {
	f.mu.Lock()
	delete(f.fail, hash)
	f.mu.Unlock()
}

// session 造一条合成会话（ID/Hash 按 TokenHash 口径，无领域词）。
func session(id, user, refreshToken string) authz.Session {
	return authz.Session{
		ID:          id,
		UserID:      user,
		Device:      "device-a",
		IP:          "198.51.100.7",
		UA:          "agent-x",
		RefreshJTI:  "jti-" + id,
		AccessHash:  authz.TokenHash("access-" + id),
		RefreshHash: authz.TokenHash(refreshToken),
		LoginAt:     time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC),
	}
}

// seq 生成唯一键/前缀（下游 Redis 可共享进程，避免用例互相污染）。
var seq atomic.Uint64

func key(t *testing.T, name string) string {
	t.Helper()
	return fmt.Sprintf("authztest:%d:%s", seq.Add(1), name)
}

func prefix(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("authztest:reg:%d:", seq.Add(1))
}

func ids(list []authz.Session) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, s.ID)
	}
	return out
}

// waitGone 轮询直到键过期（真实时钟的 store 用；容忍 CI 调度抖动）。
func waitGone(t *testing.T, store authz.SessionStore, k string) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, ok, err := store.Get(ctx, k)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if !ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("键 %q 在 3s 内未过期（TTL 语义违约）", k)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitSessionGone 轮询直到 refresh 索引查不到会话。
func waitSessionGone(t *testing.T, reg *authz.StoreRegistry, refreshHash string) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := reg.GetByRefreshHash(ctx, refreshHash)
		if errors.Is(err, authz.ErrSessionNotFound) {
			return
		}
		if err != nil {
			t.Fatalf("GetByRefreshHash() error = %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("会话在 3s 内未过期（TTL 语义违约）")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
