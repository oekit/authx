package authz_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oekit/kitx/authz"
)

// secondLockFailStore 包装 SessionStore：对 ID 锁键的第二次 SetNX 返回
// false（模拟「拉黑已完成、重枪 ID 锁时输给并发 Kick/Register」），其余
// 调用原样委托。
type secondLockFailStore struct {
	authz.SessionStore
	lockKey string
	n       int
}

func (s *secondLockFailStore) SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	if key == s.lockKey {
		s.n++
		if s.n == 2 {
			return false, nil // 只让第二次抢锁失败
		}
	}
	return s.SessionStore.SetNX(ctx, key, value, ttl)
}

// TestStoreRegistryKickContended 钉住 #236：双 hash 拉黑已完整落地、但重抢
// ID 锁失败时 Kick 返回 (false, ErrKickContended)——登记项仍存活，调用方
// 必须能区分「本就不在」（false, nil）与「已拉黑但下线未完成」（可重试），
// 否则会话幽灵态（管理端枚举得到、refresh 却不可用）静默残留。
func TestStoreRegistryKickContended(t *testing.T) {
	ctx := context.Background()
	rev := authz.NewMemRevoker()
	store := &secondLockFailStore{
		SessionStore: authz.NewMemSessionStore(),
		lockKey:      "authz:sess:lock:id:s-kick-contended",
	}
	reg, err := authz.NewStoreRegistry(rev, store)
	if err != nil {
		t.Fatalf("NewStoreRegistry: %v", err)
	}

	sess := authz.Session{
		ID:          "s-kick-contended",
		UserID:      "u1",
		RefreshHash: "rh-1",
		AccessHash:  "ah-1",
	}
	if err := reg.Register(ctx, sess, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	store.n = 0 // Register 也抢同一把 ID 锁——计数归零，Kick 的第二次抢锁才失败

	kicked, kerr := reg.Kick(ctx, sess.ID)
	if kicked {
		t.Fatal("Kick 不应报告成功（登记未删除）")
	}
	if !errors.Is(kerr, authz.ErrKickContended) {
		t.Fatalf("Kick err = %v, want ErrKickContended（#236）", kerr)
	}
	// 拉黑已落地、登记仍存活：契约两半都要成立。
	if ok, err := rev.Revoked(ctx, sess.RefreshHash); err != nil || !ok {
		t.Fatalf("refresh hash 应已拉黑: ok=%v err=%v", ok, err)
	}
	if _, err := reg.GetByID(ctx, sess.ID); err != nil {
		t.Fatalf("登记应仍存活（未删除）: %v", err)
	}
}
