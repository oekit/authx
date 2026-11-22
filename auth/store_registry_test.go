package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oekit/authx/authz"
	"github.com/oekit/authx/jwt"
)

// #196 验收：下游把 MemRegistry 换成「SessionStore + StoreRegistry 编排」后，
// kitx/auth.Flow 的登录 / 轮换 / 登出 / 强踢链路零改动通过（Flow 只依赖
// authz.SessionRegistry 契约）。
func TestFlowWithStoreRegistry(t *testing.T) {
	ctx := context.Background()
	clk := newTestClock()
	rev := authz.NewMemRevoker(authz.WithRevokerClock(clk.Now))
	store := authz.NewMemSessionStore(authz.WithSessionStoreClock(clk.Now))
	reg, err := authz.NewStoreRegistry(rev, store)
	if err != nil {
		t.Fatalf("NewStoreRegistry() error = %v", err)
	}
	m, err := jwt.NewManagerHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewManagerHS256() error = %v", err)
	}
	f, err := NewFlow(m, reg, rev,
		WithTTL(15*time.Minute, 24*time.Hour),
		WithClock(clk.Now),
		WithSignOptions(jwt.WithIssuer("kitx-test")),
	)
	if err != nil {
		t.Fatalf("NewFlow() error = %v", err)
	}
	repo := &fakeRepo{user: &User{ID: "u1"}, roles: []string{"viewer"}}

	// 登录（签发 + 会话登记一次落地）。
	pair, err := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{Device: "device-a"})
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	if list, err := reg.ListByUser(ctx, "u1"); err != nil || len(list) != 1 || list[0].ID != pair.Session.ID {
		t.Fatalf("登录后 ListByUser = (%v, %v)", list, err)
	}

	// 轮换：旧会话原子认领下线，新会话登记。
	rotated, _, err := f.RotateRefresh(ctx, repo, pair.Refresh, SessionMeta{Device: "device-b"})
	if err != nil {
		t.Fatalf("RotateRefresh() error = %v", err)
	}
	if _, err := reg.GetByRefreshHash(ctx, pair.Session.RefreshHash); !errors.Is(err, authz.ErrSessionNotFound) {
		t.Fatalf("轮换后旧会话必须下线，error = %v", err)
	}
	if list, _ := reg.ListByUser(ctx, "u1"); len(list) != 1 || list[0].ID != rotated.Session.ID {
		t.Fatalf("轮换后新会话必须在册，got %v", list)
	}
	if revoked, _ := authz.RevokedToken(ctx, rev, pair.Refresh); !revoked {
		t.Fatal("轮换后旧 refresh 必须已拉黑")
	}
	if _, err := f.ParseAccess(ctx, rotated.Access); err != nil {
		t.Fatalf("ParseAccess(新 access) error = %v", err)
	}

	// 强踢单会话：双 hash 拉黑 + 删键，资源侧立即 401。
	pair2, err := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{Device: "device-c"})
	if err != nil {
		t.Fatalf("IssuePair(pair2) error = %v", err)
	}
	if kicked, err := reg.Kick(ctx, pair2.Session.ID); err != nil || !kicked {
		t.Fatalf("Kick = (%v, %v), want (true, nil)", kicked, err)
	}
	if _, err := f.ParseAccess(ctx, pair2.Access); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("被强踢 access 必须 401，got %v", err)
	}

	// 登出：会话下线 + 双 token 拉黑，幂等。
	if err := f.Logout(ctx, rotated.Access, rotated.Refresh); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if _, err := reg.GetByRefreshHash(ctx, rotated.Session.RefreshHash); !errors.Is(err, authz.ErrSessionNotFound) {
		t.Fatalf("登出后会话必须下线，error = %v", err)
	}
	if err := f.Logout(ctx, rotated.Access, rotated.Refresh); err != nil {
		t.Fatalf("重复登出必须幂等：%v", err)
	}

	// 改密吊销钩子：用户级截断 + 全会话强踢。
	pair3, _ := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{Device: "device-d"})
	pair4, _ := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{Device: "device-e"})
	if err := f.RevokeUser(ctx, "u1", time.Now()); err != nil {
		t.Fatalf("RevokeUser() error = %v", err)
	}
	if list, _ := reg.ListByUser(ctx, "u1"); len(list) != 0 {
		t.Fatalf("改密吊销后会话残留 %v", list)
	}
	for name, access := range map[string]string{"pair3": pair3.Access, "pair4": pair4.Access} {
		if _, err := f.ParseAccess(ctx, access); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("[%s] 改密吊销后 access 必须 401，got %v", name, err)
		}
	}
}
