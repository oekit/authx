// 清零战役回归护栏（#154，2026-11-12 sweep）：issueTail 三条失败注入点都必须
// 回收刚签出的双令牌——「签发与登记一次落地」不变量全路径闭环。
package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/oekit/authx/jwt"
	bizerrors "github.com/oekit/pkg/errors"
)

// #154：issueTail 的三条失败路径（回读失败 / 会话 ID 生成失败 / Register 失败）
// 各自断言 access+refresh 均已进黑名单——此前回读失败分支裸 return，两枚签名
// 有效、完整 TTL、不在任何黑名单也不在会话登记表的无主令牌被静默丢弃，与同
// 函数另两条失败分支及 RotateRefresh「无主残留由 issueTail 自身回收」的注释
// 承诺不一致。
//
// 双 true 以 hash 口径断言：令牌串在失败路径上不外泄（返回 nil），进黑名单的
// 事实以 revokePair → RevokeToken 落到 MemRevoker 的 hash 查询为准（RevokeToken
// 内部正是 TokenHash(token) → Revoke(hash)，RevokedToken 同一哈希线）。
func TestIssueTailFailurePathsRevokeIssued(t *testing.T) {
	ctx := context.Background()

	newCaptured := func(t *testing.T, opts ...FlowOption) (*Flow, *captureRevoker) {
		t.Helper()
		f, rev, _, _ := newTestFlow(t, opts...)
		capRev := &captureRevoker{Revoker: rev}
		f.revoker = capRev
		return f, capRev
	}
	assertBothRevoked := func(t *testing.T, f *Flow, capRev *captureRevoker) {
		t.Helper()
		if got := capRev.count(); got != 2 {
			t.Fatalf("回收拉黑次数 = %d, want 2（access+refresh 双路，#154）", got)
		}
		for i, h := range capRev.hashes {
			revoked, err := capRev.Revoked(ctx, h)
			if err != nil {
				t.Fatalf("Revoked(第 %d 路 hash) error = %v", i, err)
			}
			if !revoked {
				t.Fatalf("第 %d 路拉黑未落地：hash 必须已进黑名单（#154 双 true）", i)
			}
		}
		// revokePair 单点 TTL 口径：access→ttlAccess、refresh→ttlRefresh。
		if capRev.ttls[0] != f.ttlAccess || capRev.ttls[1] != f.ttlRefresh {
			t.Fatalf("拉黑 TTL = %v, want [ttlAccess ttlRefresh] = [%v %v]", capRev.ttls, f.ttlAccess, f.ttlRefresh)
		}
	}

	t.Run("签发解析不对称不再误报（#225）", func(t *testing.T) {
		// #154 时代的真实配置形态：签发侧没配 issuer、解析侧钉 ExpectedIssuer。
		// 旧实现回读 refresh 取 jti，签发/解析不对称 ⇒ 回读必失败 ⇒ 把成功
		// 签发误判成失败并回收。#225 后两枚 jti 均由签发路径直出——同配置
		// 下 IssuePair 必须成功、零回收（这正是本修复的回归面）。
		f, capRev := newCaptured(t, WithParseOptions(jwt.WithExpectedIssuer("other")))
		pair, err := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
		if err != nil {
			t.Fatalf("签发/解析不对称是合法形态，IssuePair 不得再误报（#225）：%v", err)
		}
		if pair.Access == "" || pair.Refresh == "" {
			t.Fatal("IssuePair 成功时双令牌必须非空")
		}
		if got := capRev.count(); got != 0 {
			t.Fatalf("成功签发不得回收令牌，回收次数 = %d", got)
		}
	})

	t.Run("会话 ID 生成失败回收", func(t *testing.T) {
		f, capRev := newCaptured(t)
		old := sessionIDGen
		// 缝替换的是整个生成器，stub 自带与 newSessionID 相同的错误包装，
		// 保证断言的是真实路径的消息契约。
		sessionIDGen = func() (string, error) {
			return "", bizerrors.Wrapf(bizerrors.New("stub: broken"), "auth: 生成会话 ID 失败（crypto/rand 故障）")
		}
		t.Cleanup(func() { sessionIDGen = old })
		_, err := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
		if err == nil || !strings.Contains(err.Error(), "生成会话 ID 失败") {
			t.Fatalf("会话 ID 生成失败必须报错：%v", err)
		}
		assertBothRevoked(t, f, capRev)
	})

	t.Run("Register 失败回收", func(t *testing.T) {
		f, capRev := newCaptured(t)
		f.sessions = registerFailRegistry{f.sessions}
		_, err := f.IssuePair(ctx, &User{ID: "u1"}, SessionMeta{})
		if err == nil || !strings.Contains(err.Error(), "会话登记失败") {
			t.Fatalf("登记失败必须报错：%v", err)
		}
		assertBothRevoked(t, f, capRev)
	})
}
