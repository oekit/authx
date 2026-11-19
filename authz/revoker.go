package authz

import (
	"context"
	"sync"
	"time"

	"github.com/oekit/kitx/pwd"
	"github.com/oekit/pkg/contextx"
	"github.com/oekit/pkg/encoding"
	bizerrors "github.com/oekit/pkg/errors"
)

// TokenHash 计算令牌哈希键：sha256(token) 的小写 hex（#119 建议形态）。
//
// 这是撤销黑名单/会话注册表键空间的**唯一产出口**：所有按令牌定位的键
// （黑名单条目、会话 AccessHash/RefreshHash）都必须经本函数派生，下游不再
// 各写一份 sha256 口径（#119 下游实证：两份拷贝漂移即强踢失效）。
// #208：哈希实现单源收编 pkg/encoding.Sha256Hex（逐行等价）——此前手写的
// sha256.Sum256+hex.EncodeToString 正是「宣言靠注释对齐」的残留面；kitx 本就
// 依赖 pkg，单源落在 pkg，kitx 侧零 sha256 实现。
// 入参是完整令牌串而非 jti：绑定到具体令牌形态（同一 jti 的两个令牌串不同、
// 哈希不同，可分别吊销）。
func TokenHash(token string) string {
	return encoding.Sha256Hex([]byte(token))
}

// Revoker 撤销黑名单存储面（#119）：token 级 + 用户级两层，接口化存储。
//
// 键纪律：hash 参数必须出自 TokenHash（键空间唯一产出口），实现按「键即
// TokenHash 产物」理解与建索引，不接受任意字符串键。原始令牌串入口见
// RevokeToken / RevokedToken 助手。raw token 与 hash 的分型是有意为之：
// 会话注册表（Kick 双 hash 拉黑）只持有 hash，轮换/登出路径未必持有原始串，
// 签名收窄到 hash 级可杜绝「随手传非 TokenHash 键污染键空间」。
//
// 两层语义：
//
//   - token 级（Revoke/Revoked）：单枚令牌拉黑。remaining 是该令牌的**剩余
//     寿命**（条目 TTL，过期自然出清——过期令牌本就被 exp 拒绝，条目无需
//     长生）；已过期令牌不需要登记。
//   - 用户级（RevokeUser/RevokedUser）：截断点。at 之前签发的全部令牌判陈旧
//     （#121 改密陈旧吊销的落地口）。截断点**单调不回退**（同用户重复设置取
//     时间较大者——回退会让已判陈旧的令牌复活，是 fail-open）；不设 TTL（陈旧
//     判定随 iat 天然自限，条目随用户数线性）。
//
// 陈旧判定口径单点在 pwd.TokenStaleBefore（秒截断比较：iat 与截断点同秒不判
// 陈旧）——实现 RevokedUser 必须复用该口径，禁止另写一份比较。
//
// 存储故障契约：实现出错必须返回 error，**不得**把故障折叠成「未吊销」放行
// （fail-open 是黑名单最危险的缺省）。消费侧（kitx/auth）把查询故障归 500：
// 既不放行、也不放大成 401 全站踢下线。
type Revoker interface {
	// Revoke 吊销单枚令牌：以 hash 记黑名单，条目 TTL=remaining。
	// remaining 必须为正（已过期令牌无需登记，非正 TTL 是配置零值透传的
	// 常见形态，#65 同款纪律）。
	Revoke(ctx context.Context, hash string, remaining time.Duration) error
	// Revoked 判定单枚令牌是否已吊销（token 级）。
	Revoked(ctx context.Context, hash string) (bool, error)
	// RevokeUser 用户级吊销：at 之前签发的该用户令牌全部判陈旧（截断点单调不回退）。
	// at 不得为零值：零值截断点会让判定恒 false（一枚令牌都没吊销却返回 nil
	// ——fail-open），非正/零值是配置零值透传的常见形态，实现出口必须
	// fail-fast（与 Revoke 的 remaining 同款 #65 纪律，#188）。
	RevokeUser(ctx context.Context, userID string, at time.Time) error
	// RevokedUser 用户级判定：iat 早于截断点（秒截断，pwd.TokenStaleBefore
	// 口径）即陈旧。无截断点 ⇒ false。
	RevokedUser(ctx context.Context, userID string, iat time.Time) (bool, error)
}

// RevokeToken 以原始令牌串登记撤销（Revoker.Revoke 的薄助手：内部经
// TokenHash 落到键空间）。remaining 语义同 Revoker.Revoke。
func RevokeToken(ctx context.Context, r Revoker, token string, remaining time.Duration) error {
	return r.Revoke(ctx, TokenHash(token), remaining)
}

// RevokedToken 以原始令牌串判定撤销（Revoker.Revoked 的薄助手）。
func RevokedToken(ctx context.Context, r Revoker, token string) (bool, error) {
	return r.Revoked(ctx, TokenHash(token))
}

// MemRevoker 是 Revoker 的内存实现：并发安全（mutex 保护），零第三方依赖。
//
// 定位：单实例进程内部署的内存形态，兼作契约测试替身（#119 建议形态的
// MapRevoker 角色）。持久形态（Redis 等）由下游按 Revoker 契约落地——键前缀
// 可配、条目 TTL 语义与本实现一致。
//
// 生命周期：不启动后台 goroutine（本仓禁止裸 go func）。token 级条目过期后
// 读判即视为不在；写路径不自动清扫，Sweep 可手动回收过期条目（pkg/cache
// NoBackgroundSweep 同款哲学：清扫时机交给部署形态）。TTL 骨架（键→失效
// 时刻 + 惰性过期 + Sweep + 时钟防呆）单源在包内 ttlmap（#209），hashes 表
// 的时钟与 m.now 同源（构造期注入，之后不可变）。
type MemRevoker struct {
	mu     sync.RWMutex
	hashes *ttlmap[struct{}]    // token 级黑名单（条目失效时刻=登记时 now+remaining，#209 TTL 骨架单源）
	users  map[string]time.Time // userID → 用户级截断点（单调不回退，无 TTL）
	now    func() time.Time
}

// MemRevokerOption 是 NewMemRevoker 的函数选项。
type MemRevokerOption func(*MemRevoker)

// WithRevokerClock 注入 MemRevoker 时钟（测试确定性 TTL 边界；缺省 time.Now）。
// f 为 nil 按仓规 Option 总则②显式回退默认时钟（不把 nil 存进实例），与
// pkg/cache/pkg/webhook 的 WithClock(nil) 口径统一（#538）。
//
// 行为变更（#538）：此前 WithRevokerClock(nil) 在构造期 panic，现按默认时钟
// 正常构造。
func WithRevokerClock(f func() time.Time) MemRevokerOption {
	return func(m *MemRevoker) {
		if f == nil {
			return
		}
		m.now = f
	}
}

// NewMemRevoker 构造内存撤销黑名单（缺省时钟 time.Now）。
func NewMemRevoker(opts ...MemRevokerOption) *MemRevoker {
	m := &MemRevoker{
		now:   time.Now,
		users: make(map[string]time.Time),
	}
	for _, opt := range opts {
		opt(m)
	}
	m.hashes = newTTLMap[struct{}](m.now)
	return m
}

// Revoke 登记一条 token 级撤销（TTL=remaining）。
func (m *MemRevoker) Revoke(ctx context.Context, hash string, remaining time.Duration) error {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if hash == "" {
		return bizerrors.New("authz: Revoke 的 hash 不能为空——键必须出自 TokenHash")
	}
	if remaining <= 0 {
		return bizerrors.Newf("authz: Revoke 的 remaining 必须为正（got %v）——已过期令牌无需登记，非正 TTL 是配置零值透传的常见形态（#65 同款纪律）", remaining)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hashes.set(hash, struct{}{}, m.now().Add(remaining))
	return nil
}

// Revoked 判定 token 级撤销（过期条目视为不在）。读路径不回删（RWMutex
// 读锁；物理回收交给 Sweep）。
func (m *MemRevoker) Revoked(ctx context.Context, hash string) (bool, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, live := m.hashes.peek(hash)
	return live, nil
}

// RevokeUser 设置用户级截断点（单调不回退，取既有值与 at 的较大者——回退
// 会让已判陈旧的令牌复活）。
//
// 零值 fail-fast（#188）：at.IsZero（DB NULL/零值扫描、或调用方误传
// time.Time{} 想「吊销全部」）时直接报错，不登记——零值截断点存进去后
// RevokedUser 的判定恒 false（任何真实 iat 都不 Before 零时刻），改密/强踢
// 静默零效果且接口返回 nil 表示「成功」，正是 Revoke 对非正 remaining
// 已经 fail-fast 的同款风险（#65 纪律）。确需「撤销一切历史」的语义请用
// 显式截断点（如 time.Now()），不要让零值承担含义。
func (m *MemRevoker) RevokeUser(ctx context.Context, userID string, at time.Time) error {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if userID == "" {
		return bizerrors.New("authz: RevokeUser 的 userID 不能为空")
	}
	if at.IsZero() {
		return bizerrors.New("authz: RevokeUser 的 at 不能是零值——零值截断点判定恒 false，等于一枚令牌都没吊销（#65 同款零值透传纪律）")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.users[userID]; ok && old.After(at) {
		return nil // 截断点不回退
	}
	m.users[userID] = at
	return nil
}

// RevokedUser 用户级判定：iat 早于截断点（秒截断）即陈旧。
//
// 比较口径单点委托 pwd.TokenStaleBefore（#121 改密陈旧判定的同一份实现——
// 两处各写一份秒截断比较正是 #119/#121 要消灭的漂移形态）。
func (m *MemRevoker) RevokedUser(ctx context.Context, userID string, iat time.Time) (bool, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	since, ok := m.users[userID]
	if !ok {
		return false, nil
	}
	return pwd.TokenStaleBefore(iat, &since), nil
}

// Sweep 回收 token 级过期条目（用户级截断点不设 TTL，不回收）。
// 读路径本就把过期条目视为不在，Sweep 只影响内存占用，不影响判定语义。
func (m *MemRevoker) Sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hashes.sweep()
}
