package authz

import (
	"context"
	"errors"
	"time"
)

// ErrSessionNotFound 表示会话不在登记表（未登记 / 已过期 / 已下线）。
var ErrSessionNotFound = errors.New("authz: 会话不存在")

// Session 是一条在线会话登记项（设备/会话维度，#119）。
//
// 登记表回答「某用户在哪些设备在线」（ListByUser → Device/IP/UA/LoginAt），
// 强踢回答「如何把他踢下线」（Kick/KickUser → 双 hash 拉黑 + 删键）。
//
// 哈希字段（AccessHash/RefreshHash）是 TokenHash 产出口：登记期由编排层
// （kitx/auth）算好写入，拉黑期由注册表直接消费——原始令牌串不进登记表
// （存储面不落明文凭据）。
type Session struct {
	// ID 会话 ID（登记表主键，编排层生成；同一次登录一对令牌一枚会话 ID）。
	ID string
	// UserID 会话归属用户。
	UserID string
	// Device 设备标识（自由文本，管理端枚举/按设备辨识用；可空）。
	Device string
	// IP 登录来源 IP（审计留痕；可空）。
	IP string
	// UA 登录客户端 UA（审计留痕；可空）。
	UA string
	// Username 会话归属用户名（管理端列表展示；#218）。由编排层从
	// User.Claims["username"] 填充，kitx 不解析业务用户表；可空（调用方未注入）。
	Username string
	// RefreshJTI 会话对应的 refresh 令牌 jti（管理端展示与对账；可空）。
	RefreshJTI string
	// AccessJTI access 令牌的 jti（管理端按 jti 反查/强踢；#218）。由编排层
	// 从新签 access 令牌回读填充；可空（未登记时 jti 索引跳过该路）。
	AccessJTI string
	// AccessHash access 令牌的 TokenHash（强踢拉黑口径；可空——空则 Kick 跳过该路）。
	AccessHash string
	// RefreshHash refresh 令牌的 TokenHash（轮换认领键；必填）。
	RefreshHash string
	// LoginAt 登录/换发时刻。
	LoginAt time.Time
}

// SessionRegistry 在线会话注册表存储面（#119）：接口化存储。
//
// 生命周期契约：登记 TTL 是 refresh 令牌的**剩余寿命**（编排层以 ttlRefresh
// 登记）——会话过期即两令牌都已自然失效（编排层保证 ttlRefresh ≥ ttlAccess，
// 登记 TTL 是两令牌寿命的上界）。MemRegistry（进程内）与 StoreRegistry
// （SessionStore 编排，Redis 等持久形态，#196）都实现本契约。
//
// 强踢契约（Kick）：**双 hash 拉黑 + 删键**一次落地——只删登记不拉黑等于假
// 强踢（令牌还活着），只拉黑不删键会让会话继续被枚举为在线。拉黑落地失败时
// 登记必须保留（可重试），见 Kick 的三态返回。
type SessionRegistry interface {
	// Register 登记会话（ttl=refresh 剩余寿命，必须为正）。
	// ID 已被未过期会话占用、或 RefreshHash 已挂在另一会话上 ⇒ 报错
	// （同一 refresh 不得挂两枚会话——登记面本身也是防重放面）。
	Register(ctx context.Context, s Session, ttl time.Duration) error
	// GetByRefreshHash 按 refresh 哈希查会话（refresh 轮换的认领前置）。
	// 不在（未登记/已过期/已下线）⇒ ErrSessionNotFound。
	GetByRefreshHash(ctx context.Context, refreshHash string) (Session, error)
	// GetByID 按会话 ID 直查（管理端主键入口，#218）。不在 ⇒ ErrSessionNotFound。
	GetByID(ctx context.Context, id string) (Session, error)
	// GetByJTI 按 access/refresh 令牌的 jti 反查会话（管理端 jti 入口，#218）。
	// jti 索引在登记时由 RefreshJTI/AccessJTI 建立（非空项）；不在 ⇒
	// ErrSessionNotFound。
	GetByJTI(ctx context.Context, jti string) (Session, error)
	// ListByUser 枚举某用户的在线会话（管理端；按 LoginAt、ID 稳定排序，
	// 过期会话不出现）。返回值是快照副本，改写不影响登记表。
	ListByUser(ctx context.Context, userID string) ([]Session, error)
	// ListAll 枚举全平台在线会话（管理端全量入口，#218；排序与 ListByUser
	// 一致，过期会话不出现）。返回值是快照副本。
	ListAll(ctx context.Context) ([]Session, error)
	// Delete 仅删除登记与索引（**不拉黑**），返回会话是否存在并被删除（#218）。
	// 用于「令牌撤销已由其他路径完成、只需下线登记」的收尾（如 OAuth 撤销）；
	// 需要双 hash 拉黑的强踢请用 Kick。
	Delete(ctx context.Context, id string) (bool, error)
	// Kick 强踢单会话：双 hash 拉黑 + 删键，**原子认领**。三态契约：
	//   - (true, nil)：完整下线（拉黑与删键都已落地）；
	//   - (false, nil)：登记不存在（幂等强踢的常态 / 轮换竞态的败方 / 同 ID
	//     会话已重建的 ABA 败方，#136）；
	//   - (false, err)：拉黑或下线前置落地失败，登记**保留**（可重试）。
	//
	// 原子认领（claim）是 refresh 轮换防重放的拍板点：并发轮换/强踢竞争同一
	// 会话时恰有一个调用拿到 true，其余按败方拒绝——「旧 refresh 二次使用被拒」
	// 不靠时序运气。ABA 提示（#136）：解锁-重锁窗口里同 ID 会话可能被「踢掉 +
	// 重建」，实现必须按登记项**身份**复核（而非存在性），不得误删重建会话。
	Kick(ctx context.Context, id string) (bool, error)
	// KickUser 强踢某用户全部在线会话（#119 强踢全会话；改密吊销钩子的落地
	// 一半）。返回完整下线的会话数；部分失败时已踢的不回滚，错误聚合上抛
	// （errors.Join）。
	KickUser(ctx context.Context, userID string) (int, error)
}

// MemRegistry 是 SessionRegistry 的内存实现：基于 MemSessionStore + StoreRegistry
// 编排层（#196 起不再维护第二套索引实现），与 MemRevoker 配对使用（Kick 的
// 双 hash 拉黑经构造注入的 Revoker 落地）。
//
// 定位与 MemRevoker 一致：单实例进程内形态 + 契约测试替身。不启动后台
// goroutine——过期会话读判即视为不在，Sweep 可手动回收。
type MemRegistry struct {
	*StoreRegistry
	store *MemSessionStore
	now   func() time.Time
}

var _ SessionRegistry = (*MemRegistry)(nil)

// MemRegistryOption 是 NewMemRegistry 的函数选项。
type MemRegistryOption func(*MemRegistry)

// WithRegistryClock 注入 MemRegistry 时钟（缺省 time.Now；时钟同时用于内存
// store 的 TTL 判定）。f 为 nil 按仓规 Option 总则②显式回退默认时钟（不把
// nil 存进实例），与 pkg/cache/pkg/webhook 的 WithClock(nil) 口径统一（#538，
// WithRevokerClock/WithSessionStoreClock 同批）。
//
// 行为变更（#538）：此前 WithRegistryClock(nil) 在构造期 panic，现按默认时钟
// 正常构造。
func WithRegistryClock(f func() time.Time) MemRegistryOption {
	return func(m *MemRegistry) {
		if f == nil {
			return
		}
		m.now = f
	}
}

// NewMemRegistry 构造内存会话注册表。rev 是 Kick/KickUser 双 hash 拉黑的
// 落地口，必须非 nil——强踢无拉黑等于假强踢（#65 同款零值透传纪律，构造期
// fail-fast panic）。
func NewMemRegistry(rev Revoker, opts ...MemRegistryOption) *MemRegistry {
	if rev == nil {
		panic("authz: NewMemRegistry 需要非 nil Revoker——Kick/KickUser 的双 hash 拉黑经它落地，无拉黑的强踢是假强踢")
	}
	m := &MemRegistry{now: time.Now}
	for _, opt := range opts {
		opt(m)
	}
	m.store = NewMemSessionStore(WithSessionStoreClock(m.now))
	reg, err := NewStoreRegistry(rev, m.store)
	if err != nil {
		// 构造参数已在本函数内校验（rev 非 nil、store 非 nil），走到这里属于
		// 编程错误：与同包构造期 fail-fast 口径一致。
		panic("authz: NewMemRegistry 构造 StoreRegistry 失败: " + err.Error())
	}
	m.StoreRegistry = reg
	return m
}

// Sweep 回收过期登记（读路径已把过期会话视为不在，Sweep 只影响内存占用）。
func (m *MemRegistry) Sweep() {
	m.store.Sweep()
}
