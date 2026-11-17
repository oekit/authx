package authz

import "time"

// ttlmap 是 authz 包内私有的 TTL 骨架（#209）：「键 → (载荷, 失效时刻)」的
// 泛型 map，收编 MemSessionStore（kv 主键表 / sets 集合索引两张表）与
// MemRevoker（hashes 黑名单）此前各自维护的同一套机制——惰性过期、Sweep、
// 构造注入时钟。两侧差异（string 载体 vs 集合指针、读判是否回删）在 entry
// 载体类型与调用方逻辑里消化，骨架只管「键与失效时刻」这一层共同契约。
//
// 这是会话注册表/撤销黑名单的**存储契约**辅助件，不是 cache-aside 缓存：
// 不与 pkg/cache.LocalCache 合并——缓存过期可以回源重取，这里的条目是
// 登记事实（会话索引、吊销黑名单），过期即消灭，无回源。
//
// 并发契约：ttlmap 自身**非并发安全**，调用方必须持有所属实现自己的锁
// （MemSessionStore.mu / MemRevoker.mu）——两侧一张锁管多张表（Del/TTL 要
// 原子跨 kv 与 sets、users 截断点与 hashes 黑名单同锁），锁不能下沉到 ttlmap。
//
// 生命周期：不启动后台 goroutine（本仓禁止裸 go func）。get/ttl/expire/
// extend 读判时惰性出清过期项（物理回收不等待 Sweep）；peek 只读不出清，
// 供 RWMutex 读锁路径（MemRevoker.Revoked）使用；Sweep 交给部署形态手动
// 触发（pkg/cache NoBackgroundSweep 同款哲学）。
//
// 时间口径：条目「存活」当且仅当 now < expiresAt（到点即亡）。时钟构造注入；
// nil fail-fast 是包内不变量防呆（各构造函数在应用 Option 前已把时钟缺省为
// time.Now，Option 层 nil 回退默认见 WithRevokerClock/WithSessionStoreClock
// 的 #538 口径——正常路径到不了这里）。
type ttlmap[V any] struct {
	m   map[string]ttlEntry[V]
	now func() time.Time
}

// ttlEntry 是 ttlmap 的条目：载荷 + 失效时刻。
type ttlEntry[V any] struct {
	value     V
	expiresAt time.Time
}

// newTTLMap 构造 ttlmap（时钟必须注入；nil 是包内编程错误，fail-fast）。
func newTTLMap[V any](now func() time.Time) *ttlmap[V] {
	if now == nil {
		panic("authz: ttlmap 收到 nil 时钟——各构造函数必须先缺省 time.Now 再注入（#538 后 Option 层 nil 已回退默认，正常路径到不了这里）")
	}
	return &ttlmap[V]{m: make(map[string]ttlEntry[V]), now: now}
}

// get 取活条目并惰性出清过期项（写操作——RWMutex 读锁路径用 peek）。
func (m *ttlmap[V]) get(key string) (V, bool) {
	var zero V
	e, ok := m.m[key]
	if !ok {
		return zero, false
	}
	if !m.now().Before(e.expiresAt) {
		delete(m.m, key)
		return zero, false
	}
	return e.value, true
}

// peek 只读取活条目（过期视同不存在，**不回删**——可在 RWMutex 读锁下调用，
// MemRevoker.Revoked 的读路径）。
func (m *ttlmap[V]) peek(key string) (V, bool) {
	var zero V
	e, ok := m.m[key]
	if !ok {
		return zero, false
	}
	if !m.now().Before(e.expiresAt) {
		return zero, false
	}
	return e.value, true
}

// set 写入条目（覆盖既有值与失效时刻；expiresAt 是绝对时刻）。
func (m *ttlmap[V]) set(key string, value V, expiresAt time.Time) {
	m.m[key] = ttlEntry[V]{value: value, expiresAt: expiresAt}
}

// expire 重设活条目的失效时刻为 expiresAt（绝对值语义），返回条目是否存在
// 且未过期（不存在/已过期都不改写——过期条目顺手出清）。
func (m *ttlmap[V]) expire(key string, expiresAt time.Time) bool {
	e, ok := m.m[key]
	if !ok {
		return false
	}
	if !m.now().Before(e.expiresAt) {
		delete(m.m, key)
		return false
	}
	e.expiresAt = expiresAt
	m.m[key] = e
	return true
}

// extend 把活条目的失效时刻延长到至少 expiresAt——**只延长、不缩短**
// （SAdd 的集合 TTL 语义：短寿命会话登记不得把长寿命会话从索引里提前抹掉）。
// 返回条目是否存在且未过期。
func (m *ttlmap[V]) extend(key string, expiresAt time.Time) bool {
	e, ok := m.m[key]
	if !ok {
		return false
	}
	if !m.now().Before(e.expiresAt) {
		delete(m.m, key)
		return false
	}
	if e.expiresAt.Before(expiresAt) {
		e.expiresAt = expiresAt
		m.m[key] = e
	}
	return true
}

// ttl 返回活条目的剩余寿命（不存在/已过期 ⇒ (0, false)，过期条目顺手出清）。
func (m *ttlmap[V]) ttl(key string) (time.Duration, bool) {
	e, ok := m.m[key]
	if !ok {
		return 0, false
	}
	now := m.now()
	if !now.Before(e.expiresAt) {
		delete(m.m, key)
		return 0, false
	}
	return e.expiresAt.Sub(now), true
}

// remove 删除条目（幂等，无论是否存在）。
func (m *ttlmap[V]) remove(key string) {
	delete(m.m, key)
}

// sweep 回收全部过期条目（读路径本就把过期项视为不存在，Sweep 只影响内存
// 占用，不影响判定语义）。
func (m *ttlmap[V]) sweep() {
	now := m.now()
	for key, e := range m.m {
		if !now.Before(e.expiresAt) {
			delete(m.m, key)
		}
	}
}

// len 返回当前条目数（含尚未出清的过期条目——供测试断言 Sweep 效果；
// 调用方须持有所属实现的锁）。
func (m *ttlmap[V]) len() int {
	return len(m.m)
}
