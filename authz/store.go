package authz

import (
	"context"
	"sync"
	"time"

	"github.com/oekit/pkg/contextx"
	bizerrors "github.com/oekit/pkg/errors"
)

// SessionStore 是 SessionRegistry 编排层依赖的最小存储面（#196）：键值 +
// 集合 + TTL 原语。kitx 只依赖这 8 个方法，下游把 Redis 等持久存储包成
// 10 来行适配器即可复用整套注册/轮换/强踢编排（StoreRegistry）。
//
// 键由编排层生成（含 WithStorePrefix 命名空间），对 store 实现是不透明字符串；
// 实现不得解析/改写键。所有方法必须并发安全且跨实例安全（同一键的并发
// SetNX/Del 语义与单实例一致）。
//
// 生命周期硬约束：**实现创建的每个键都必须带过期时间**（SetNX/SAdd 的 ttl、
// Expire 的 ttl 均必须为正）。无过期键会让会话索引永久驻留，也会让 Kick 无法
// 计算剩余寿命——TTL 探测失败时必须返回 error，不得回落成「永不过期」。
//
// 存储故障契约（与 Revoker 同口径）：实现出错必须返回 error，不得把故障折叠
// 成「不存在/已删除」——强踢把存储故障误判成 not-found 就是假下线。
type SessionStore interface {
	// Get 返回 key 的当前值。key 不存在或已过期 ⇒ ("", false, nil)；
	// 存储故障 ⇒ ("", false, err)。
	Get(ctx context.Context, key string) (string, bool, error)

	// SetNX 仅当 key 不存在（或已过期）时原子写入 value 并设置 ttl，返回是否
	// 写入成功。**原子性是多实例强踢/登记的拍板点**：并发 SetNX 同一 key 必须
	// 恰有一个 true。ttl 必须为正（<=0 返回 error）；已存在的 key 不得被覆盖、
	// 不得刷新其 TTL。
	SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)

	// Del 原子删除 key（字符串键或集合键），返回 key 是否存在并被删除
	// （不存在/已过期 ⇒ false）。Del(missing) 不是错误（幂等清理）。
	Del(ctx context.Context, key string) (bool, error)

	// SAdd 原子把 member 加入集合 key，并把集合 TTL **延长到至少 ttl**：
	// 集合不存在时创建并设置 ttl；已存在时 TTL 取「现有剩余寿命」与 ttl 的
	// 较大者——**只延长、不缩短**（一个用户的会话寿命长短不一，短寿命会话
	// 登记不得把长寿命会话从索引里提前抹掉）。ttl 必须为正。
	SAdd(ctx context.Context, key, member string, ttl time.Duration) error

	// SRem 从集合 key 移除 member（集合/成员不存在照常成功，幂等）。
	SRem(ctx context.Context, key, member string) error

	// SMembers 返回集合全部成员的快照（集合不存在 ⇒ 空切片，无错误）。
	// 顺序不保证；调用方自行排序。
	SMembers(ctx context.Context, key string) ([]string, error)

	// Expire 把已存在 key 的过期时间重设为 ttl（不延长/不缩短的语义由调用方
	// 判断），返回 key 是否存在。ttl 必须为正。
	Expire(ctx context.Context, key string, ttl time.Duration) (bool, error)

	// TTL 返回 key 的剩余寿命。key 不存在/已过期 ⇒ (0, false, nil)；
	// key 存在且带过期时间 ⇒ (remaining, true, nil)。实现不得创建无过期键；
	// 若探测到无过期键应返回 error（契约违约），不得以 0/false 静默放行。
	TTL(ctx context.Context, key string) (time.Duration, bool, error)
}

// memStoreSet 是内存 store 的集合项（成员集；集合的失效时刻由 ttlmap 条目
// 承载，#209 TTL 骨架单源）。
type memStoreSet struct {
	members map[string]struct{}
}

// MemSessionStore 是 SessionStore 的内存参考实现：并发安全（mutex 保护），
// 零第三方依赖，可作 StoreRegistry 的单实例/multi-instance 测试替身。
//
// 过期语义：读路径惰性出清（过期键视作不存在），Sweep 可手动回收；不启动
// 后台 goroutine（本仓禁止裸 go func）。TTL 骨架（键→失效时刻 + 惰性过期 +
// Sweep + 时钟防呆）单源在包内 ttlmap（#209）——kv 与 sets 两张表共用一份
// 实现，时钟取构造注入的 m.now（与 ttlmap 内部判定同一时钟源，构造后不可变）。
type MemSessionStore struct {
	mu   sync.Mutex
	now  func() time.Time
	kv   *ttlmap[string]       // 主键值表（string 载体）
	sets *ttlmap[*memStoreSet] // 用户会话索引（集合键，指针载荷原地改成员）
}

var _ SessionStore = (*MemSessionStore)(nil)

// MemSessionStoreOption 是 NewMemSessionStore 的函数选项。
type MemSessionStoreOption func(*MemSessionStore)

// WithSessionStoreClock 注入内存 store 时钟（测试确定性 TTL 边界；缺省
// time.Now）。f 为 nil 按仓规 Option 总则②显式回退默认时钟（不把 nil 存进
// 实例），与 pkg/cache/pkg/webhook 的 WithClock(nil) 口径统一（#538）。
//
// 行为变更（#538）：此前 WithSessionStoreClock(nil) 在构造期 panic，现按默认
// 时钟正常构造。
func WithSessionStoreClock(f func() time.Time) MemSessionStoreOption {
	return func(m *MemSessionStore) {
		if f == nil {
			return
		}
		m.now = f
	}
}

// NewMemSessionStore 构造内存 SessionStore（缺省时钟 time.Now）。
func NewMemSessionStore(opts ...MemSessionStoreOption) *MemSessionStore {
	m := &MemSessionStore{now: time.Now}
	for _, opt := range opts {
		opt(m)
	}
	m.kv = newTTLMap[string](m.now)
	m.sets = newTTLMap[*memStoreSet](m.now)
	return m
}

// Get 返回键值（契约见 SessionStore）。
func (m *MemSessionStore) Get(ctx context.Context, key string) (string, bool, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.kv.get(key)
	if !ok {
		return "", false, nil
	}
	return value, true, nil
}

// SetNX 原子写入（契约见 SessionStore）。
func (m *MemSessionStore) SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if ttl <= 0 {
		return false, bizerrors.Newf("authz: MemSessionStore.SetNX 的 ttl 必须为正（got %v）", ttl)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.kv.get(key); ok {
		return false, nil
	}
	m.kv.set(key, value, m.now().Add(ttl))
	return true, nil
}

// Del 删除键（契约见 SessionStore；字符串键与集合键同一命名空间，均可删）。
func (m *MemSessionStore) Del(ctx context.Context, key string) (bool, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	found := false
	if _, ok := m.kv.get(key); ok {
		m.kv.remove(key)
		found = true
	}
	if _, ok := m.sets.get(key); ok {
		m.sets.remove(key)
		found = true
	}
	return found, nil
}

// SAdd 加入集合并延长 TTL（契约见 SessionStore）。
func (m *MemSessionStore) SAdd(ctx context.Context, key, member string, ttl time.Duration) error {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if ttl <= 0 {
		return bizerrors.Newf("authz: MemSessionStore.SAdd 的 ttl 必须为正（got %v）", ttl)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	set, ok := m.sets.get(key)
	if !ok {
		set = &memStoreSet{members: make(map[string]struct{})}
		m.sets.set(key, set, now.Add(ttl))
	} else {
		m.sets.extend(key, now.Add(ttl))
	}
	set.members[member] = struct{}{}
	return nil
}

// SRem 移除集合成员（契约见 SessionStore）。
func (m *MemSessionStore) SRem(ctx context.Context, key, member string) error {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.sets.get(key)
	if !ok {
		return nil
	}
	delete(set.members, member)
	if len(set.members) == 0 {
		m.sets.remove(key)
	}
	return nil
}

// SMembers 返回集合快照（契约见 SessionStore）。
func (m *MemSessionStore) SMembers(ctx context.Context, key string) ([]string, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.sets.get(key)
	if !ok {
		return []string{}, nil
	}
	out := make([]string, 0, len(set.members))
	for member := range set.members {
		out = append(out, member)
	}
	return out, nil
}

// Expire 重设键过期时间（契约见 SessionStore）。
func (m *MemSessionStore) Expire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if ttl <= 0 {
		return false, bizerrors.Newf("authz: MemSessionStore.Expire 的 ttl 必须为正（got %v）", ttl)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	expiresAt := m.now().Add(ttl)
	if m.kv.expire(key, expiresAt) {
		return true, nil
	}
	if m.sets.expire(key, expiresAt) {
		return true, nil
	}
	return false, nil
}

// TTL 返回剩余寿命（契约见 SessionStore）。
func (m *MemSessionStore) TTL(ctx context.Context, key string) (time.Duration, bool, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if remaining, ok := m.kv.ttl(key); ok {
		return remaining, true, nil
	}
	if remaining, ok := m.sets.ttl(key); ok {
		return remaining, true, nil
	}
	return 0, false, nil
}

// Sweep 回收过期键与集合（读路径本就把过期项视为不存在，Sweep 只影响内存占用）。
// 仅内存实现提供；持久 store 依赖后端原生 TTL。
func (m *MemSessionStore) Sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kv.sweep()
	m.sets.sweep()
}
