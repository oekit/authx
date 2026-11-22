package auth

import (
	"context"
	"testing"

	"github.com/oekit/authx/jwt"
)

// #204 回归：User.Audience 签发为标准 aud 声明（OAuth 场景 = client_id），
// RotateRefresh 自动继承旧令牌的 aud（轮换不丢受众）。

func TestIssuePairAudience_204(t *testing.T) {
	f, _, _, _ := newTestFlow(t)
	u := &User{ID: "u1", Audience: []string{"client-a", "client-b"}}
	pair, err := f.IssuePair(t.Context(), u, SessionMeta{IP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := f.jwt.ParseTyped(jwt.TokenAccess, pair.Access)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Audience) != 2 || claims.Audience[0] != "client-a" {
		t.Fatalf("aud = %v, want [client-a client-b]", claims.Audience)
	}
}

func TestIssuePairNoAudience_204(t *testing.T) {
	f, _, _, _ := newTestFlow(t)
	u := &User{ID: "u1"}
	pair, err := f.IssuePair(t.Context(), u, SessionMeta{})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := f.jwt.ParseTyped(jwt.TokenAccess, pair.Access)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Audience) != 0 {
		t.Fatalf("无 Audience 时 aud 应缺失, got %v", claims.Audience)
	}
}

func TestRotateRefreshAudienceInheritance_204(t *testing.T) {
	f, _, reg, _ := newTestFlow(t)
	repo := &fakeRepo{user: &User{
		ID:     "u1",
		Claims: map[string]any{"team": "infra"},
	}}
	u := &User{
		ID:       "u1",
		Audience: []string{"client-x"},
		Claims:   map[string]any{"team": "infra"},
	}
	pair, err := f.IssuePair(t.Context(), u, SessionMeta{IP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	// 验证旧令牌 aud
	oc, err := f.jwt.ParseTyped(jwt.TokenAccess, pair.Access)
	if err != nil {
		t.Fatal(err)
	}
	if len(oc.Audience) != 1 || oc.Audience[0] != "client-x" {
		t.Fatalf("旧令牌 aud = %v, want [client-x]", oc.Audience)
	}

	newPair, nu, err := f.RotateRefresh(context.Background(), repo, pair.Refresh, SessionMeta{IP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	nc, err := f.jwt.ParseTyped(jwt.TokenAccess, newPair.Access)
	if err != nil {
		t.Fatal(err)
	}
	if len(nc.Audience) != 1 || nc.Audience[0] != "client-x" {
		t.Fatalf("轮换后 aud = %v, want [client-x]（轮换不丢受众 #204）", nc.Audience)
	}
	if nu.Audience[0] != "client-x" {
		t.Fatalf("返回的 User.Audience = %v, want [client-x]", nu.Audience)
	}
	// Claims 继承（既有行为回归）
	if nc.Extra["team"] != "infra" {
		t.Fatalf("轮换后 Claims 应继承, team = %v", nc.Extra["team"])
	}
	// 会话仍在 reg（IssuePair 登记）✓
	_ = reg
}
