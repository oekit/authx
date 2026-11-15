package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/oekit/kitx/uidgen"
	"github.com/oekit/logx"
)

// log 是本包的懒解析日志器（SDK/基础包规范：Delegating，禁止 Default()）。
var log = logx.Delegating("kitx/authz")

const (
	// defaultStorePrefix 是 StoreRegistry 的缺省键命名空间。
	defaultStorePrefix = "authz:sess:"
	// sessionOpLockTTL 是会话操作锁的 TTL：登记/强踢是毫秒级网络操作，30s
	// 覆盖存储抖动且落在治理类（≤60s）区间内；进程在持锁期间崩溃时锁自动
	// 过期，不会永久卡住该会话 ID。
	sessionOpLockTTL = 30 * time.Second
	// cleanupTimeout 是尽力清理/释放锁的超时（与探测类 ≤10s 同量级）。
	cleanupTimeout = 5 * time.Second
)

// storedSession 是主键的落盘形态：Session + 登记代次（Generation）。
//
// 代次是 ABA 判定的身份依据（对应旧 MemRegistry 的 *regEntry 指针比较）：
// 同 ID 会话被踢掉后重建会得到新代次，在途 Kick 重锁后按代次复核，不会误删
// 重建会话（#136）；refresh 索引也携带代次，防止「同 ID + 同 refresh」重建
// 被旧 Kick 的索引清理误删。
type storedSession struct {
	Session    Session `json:"session"`
	Generation string  `json:"generation"`
}

// refreshMount 是 refresh 索引的值：会话 ID + 登记代次。
type refreshMount struct {
	ID         string `json:"id"`
	Generation string `json:"generation"`
}

// StoreRegistry 是基于 SessionStore 的会话注册表编排实现（#196）：把注册冲突、
// refreshHash 唯一挂载、Kick 三态（原子认领 + 双 hash 拉黑 + 删键）与
// KickUser 聚合计数集中在本层，下游只需实现 SessionStore（Redis 等适配器约
// 10 行）即可替换 MemRegistry，kitx/auth.Flow 的登录/轮换/登出/强踢链路零改动。
//
// 键布局（prefix 由 WithStorePrefix 配置，缺省 authz:sess:）：
//
//	<prefix>id:<sessionID>         主键（storedSession JSON：Session + 登记代次）
//	<prefix>refresh:<refreshHash>  refresh 反查/唯一挂载（refreshMount JSON）
//	<prefix>user:<userID>          用户索引集合（成员=sessionID）
//	<prefix>lock:id:<sessionID>    会话操作锁（SetNX + TTL）
//	<prefix>lock:refresh:<hash>    refresh 索引变更锁（SetNX + TTL）
//
// 并发拍板：Register 全程持 ID 锁（主键/refresh/用户索引一次落地）；Kick 只在
// 「读取快照」与「代次复核 + 删主键 + 清索引」两个短临界区持 ID 锁，拉黑调用
// 在锁外执行（与旧 MemRegistry 的解锁-重锁窗口同形，#136）——并发 Kick 各自
// 幂等拉黑，重锁后只有代次仍匹配的一方删键成功并返回 true。refresh 索引的
// 挂载/摘除另抢 refresh 锁，靠代次比对避免 ABA 误删。
//
// 锁持有时间受 sessionOpLockTTL 约束，存储操作异常慢时锁会自然过期——实现应
// 保证 SessionStore 调用远快于 30s。锁释放失败只记日志（锁会在 TTL 后自愈），
// 不影响已落地结果的三态语义。
type StoreRegistry struct {
	rev    Revoker
	store  SessionStore
	prefix string
}

var _ SessionRegistry = (*StoreRegistry)(nil)

// StoreRegistryOption 是 NewStoreRegistry 的函数选项。
type StoreRegistryOption func(*StoreRegistry)

// WithStorePrefix 配置键命名空间（多租户/多环境隔离）。空串显式回退缺省
// "authz:sess:"；非空且未以 ':' 结尾时自动补 ':'，保证键为 prefix+"id:"+...
// 的可读形态。store 实现无需感知 prefix——它只拿到已拼好的不透明键。
func WithStorePrefix(prefix string) StoreRegistryOption {
	return func(r *StoreRegistry) { r.prefix = prefix }
}

// NewStoreRegistry 构造基于 SessionStore 的会话注册表。构造期 fail-fast：
// rev/store 任一为 nil 直接报错（无拉黑的强踢是假强踢；无存储的注册表是空壳）。
func NewStoreRegistry(rev Revoker, store SessionStore, opts ...StoreRegistryOption) (*StoreRegistry, error) {
	if rev == nil {
		return nil, fmt.Errorf("authz: NewStoreRegistry 需要非 nil Revoker——Kick/KickUser 的双 hash 拉黑经它落地")
	}
	if store == nil {
		return nil, fmt.Errorf("authz: NewStoreRegistry 需要非 nil SessionStore")
	}
	r := &StoreRegistry{rev: rev, store: store, prefix: defaultStorePrefix}
	for _, opt := range opts {
		opt(r)
	}
	r.prefix = normalizeStorePrefix(r.prefix)
	return r, nil
}

// Register 登记会话（契约见 SessionRegistry）。
func (r *StoreRegistry) Register(ctx context.Context, s Session, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.ID == "" || s.UserID == "" || s.RefreshHash == "" {
		return fmt.Errorf("authz: Register 的 ID/UserID/RefreshHash 必填（ID=登记主键、RefreshHash=轮换认领键）")
	}
	if ttl <= 0 {
		return fmt.Errorf("authz: Register 的 ttl 必须为正（got %v）——ttl 是 refresh 剩余寿命，零值透传等于登记长生会话（#65 同款纪律）", ttl)
	}
	release, acquired, err := r.acquireLock(ctx, r.idLockKey(s.ID))
	if err != nil {
		return err
	}
	if !acquired {
		return fmt.Errorf("authz: 会话 ID %q 正在登记/强踢中，请稍后重试", s.ID)
	}
	defer release()

	gen, err := newSessionGeneration()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(storedSession{Session: s, Generation: gen})
	if err != nil {
		return fmt.Errorf("authz: 会话序列化失败: %w", err)
	}
	// 主键 SetNX 是「登记不可覆盖」的拍板点（ID 锁之外的第二道原子闸）。
	ok, err := r.store.SetNX(ctx, r.idKey(s.ID), string(payload), ttl)
	if err != nil {
		return fmt.Errorf("authz: 登记会话主键失败: %w", err)
	}
	if !ok {
		return fmt.Errorf("authz: 会话 ID %q 已登记——登记不可覆盖，先 Kick 再登记", s.ID)
	}
	if err := r.mountRefresh(ctx, s.ID, s.RefreshHash, gen, ttl); err != nil {
		return errors.Join(err, r.rollbackRegistration(ctx, s))
	}
	// 用户索引集合 TTL 只延长不缩短（SAdd 契约）：短寿命会话不得提前抹掉
	// 同用户的长寿命会话。
	if err := r.store.SAdd(ctx, r.userKey(s.UserID), s.ID, ttl); err != nil {
		return errors.Join(fmt.Errorf("authz: 登记用户索引失败: %w", err), r.rollbackRegistration(ctx, s))
	}
	return nil
}

// GetByRefreshHash 按 refresh 哈希查会话（契约见 SessionRegistry）。
func (r *StoreRegistry) GetByRefreshHash(ctx context.Context, refreshHash string) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	raw, ok, err := r.store.Get(ctx, r.refreshKey(refreshHash))
	if err != nil {
		return Session{}, fmt.Errorf("authz: 查询 refreshHash 索引失败: %w", err)
	}
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	mount, err := decodeRefreshMount(raw)
	if err != nil {
		return Session{}, fmt.Errorf("authz: refreshHash 索引数据损坏: %w", err)
	}
	stored, live, err := r.getSession(ctx, mount.ID)
	if err != nil {
		return Session{}, err
	}
	if !live {
		// 索引残留（主键已过期/被删）：语义等同不在；残留索引由 TTL 或下次
		// Register 的挂载清理出清（此处无锁，不做删除以免误删并发重建的挂载）。
		return Session{}, ErrSessionNotFound
	}
	// 代次复核（#136 ABA）：索引必须指向「当前这次登记」，同 ID 重建后的新
	// 代次不认旧索引。
	if stored.Generation != mount.Generation || stored.Session.ID != mount.ID || stored.Session.RefreshHash != refreshHash {
		return Session{}, ErrSessionNotFound
	}
	return stored.Session, nil
}

// ListByUser 枚举某用户的在线会话（契约见 SessionRegistry）。
func (r *StoreRegistry) ListByUser(ctx context.Context, userID string) ([]Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	members, err := r.store.SMembers(ctx, r.userKey(userID))
	if err != nil {
		return nil, fmt.Errorf("authz: 枚举用户会话索引失败: %w", err)
	}
	out := make([]Session, 0, len(members))
	for _, id := range members {
		stored, live, err := r.getSession(ctx, id)
		if err != nil {
			return nil, err
		}
		// 过期/已下线/索引错挂的成员不出现（快照语义）。
		if !live || stored.Session.UserID != userID {
			continue
		}
		out = append(out, stored.Session)
	}
	// 稳定排序（LoginAt → ID）：管理端枚举顺序确定，不随集合遍历序漂。
	slices.SortFunc(out, func(a, b Session) int {
		if c := a.LoginAt.Compare(b.LoginAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

// Kick 强踢单会话（契约见 SessionRegistry 的三态返回）。
//
// 时序（与旧 MemRegistry 的 #136 解锁-重锁窗口同构）：
//
//	ID 锁内读快照（Session + 登记代次 + 剩余寿命）→ 释放锁
//	→ 锁外双 hash 拉黑（失败 ⇒ (false, err)，登记保留可重试）
//	→ 重抢 ID 锁，按**代次**复核：代次已变/主键已不在 ⇒ 败方 (false, nil)
//	→ 删主键（下线生效点）→ 尽力清理 refresh/用户索引 → (true, nil)
func (r *StoreRegistry) Kick(ctx context.Context, id string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	idRelease, acquired, err := r.acquireLock(ctx, r.idLockKey(id))
	if err != nil {
		return false, err
	}
	if !acquired {
		// 另一 Register/Kick 正在临界区：按不存在返回（幂等强踢常态）。
		return false, nil
	}
	stored, live, err := r.getSession(ctx, id)
	if err != nil {
		idRelease()
		return false, err
	}
	if !live {
		idRelease()
		return false, nil
	}
	remaining, ttlOK, err := r.store.TTL(ctx, r.idKey(id))
	if err != nil {
		idRelease()
		return false, fmt.Errorf("authz: 读取会话剩余寿命失败: %w", err)
	}
	idRelease()
	if !ttlOK || remaining <= 0 {
		// 自然过期：不拉黑（令牌本就过期），索引残留由 TTL/下次挂载清理。
		return false, nil
	}

	var errs []error
	if stored.Session.AccessHash != "" {
		if err := r.rev.Revoke(ctx, stored.Session.AccessHash, remaining); err != nil {
			errs = append(errs, fmt.Errorf("拉黑 access: %w", err))
		}
	}
	if stored.Session.RefreshHash != "" {
		if err := r.rev.Revoke(ctx, stored.Session.RefreshHash, remaining); err != nil {
			errs = append(errs, fmt.Errorf("拉黑 refresh: %w", err))
		}
	}
	if len(errs) > 0 {
		// 双路拉黑失败聚合；登记保留（不信「主键已删但令牌还活着」的假下线）。
		return false, errors.Join(errs...)
	}

	// 重锁后按代次复核（#136）：解锁-重锁窗口里同 ID 会话可能被其它 Kick
	// 踢掉 + Register 重建，只判存在性会误删重建会话。
	idRelease, acquired, err = r.acquireLock(ctx, r.idLockKey(id))
	if err != nil {
		return false, err
	}
	if !acquired {
		return false, nil // 认领输给并发 Kick/Register：本调用不删键
	}
	defer idRelease()
	cur, live, err := r.getSession(ctx, id)
	if err != nil {
		return false, err
	}
	if !live || cur.Generation != stored.Generation {
		return false, nil
	}
	deleted, err := r.store.Del(ctx, r.idKey(id))
	if err != nil {
		return false, fmt.Errorf("authz: 删除会话主键失败（登记保留，可重试）: %w", err)
	}
	if !deleted {
		return false, nil // 重锁后自然过期：按不存在返回
	}
	r.cleanupAfterKick(ctx, stored)
	return true, nil
}

// KickUser 强踢某用户全部在线会话（契约见 SessionRegistry）。
func (r *StoreRegistry) KickUser(ctx context.Context, userID string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	members, err := r.store.SMembers(ctx, r.userKey(userID))
	if err != nil {
		return 0, fmt.Errorf("authz: 枚举用户会话索引失败: %w", err)
	}
	count := 0
	var errs []error
	for _, id := range members {
		kicked, err := r.Kick(ctx, id)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if kicked {
			count++
		}
	}
	return count, errors.Join(errs...)
}

// mountRefresh 在 refresh 锁内唯一挂载 refreshHash（调用方已持有 ID 锁）。
// 已挂载到**同代次**的活会话 ⇒ 报错；挂载到已过期会话/旧代次残留 ⇒ 清残后
// 重试一次。
func (r *StoreRegistry) mountRefresh(ctx context.Context, id, refreshHash, gen string, ttl time.Duration) error {
	release, acquired, err := r.acquireLock(ctx, r.refreshLockKey(refreshHash))
	if err != nil {
		return err
	}
	if !acquired {
		return fmt.Errorf("authz: refreshHash 索引正在变更（挂载/强踢），请稍后重试")
	}
	defer release()

	value, err := encodeRefreshMount(refreshMount{ID: id, Generation: gen})
	if err != nil {
		return fmt.Errorf("authz: refreshHash 索引序列化失败: %w", err)
	}
	key := r.refreshKey(refreshHash)
	for attempt := 0; attempt < 2; attempt++ {
		ok, err := r.store.SetNX(ctx, key, value, ttl)
		if err != nil {
			return fmt.Errorf("authz: 挂载 refreshHash 失败: %w", err)
		}
		if ok {
			return nil
		}
		raw, exists, err := r.store.Get(ctx, key)
		if err != nil {
			return fmt.Errorf("authz: 查询 refreshHash 索引失败: %w", err)
		}
		if exists {
			cur, err := decodeRefreshMount(raw)
			if err != nil {
				return fmt.Errorf("authz: refreshHash 索引数据损坏: %w", err)
			}
			stored, live, err := r.getSession(ctx, cur.ID)
			if err != nil {
				return err
			}
			if live && stored.Generation == cur.Generation {
				return fmt.Errorf("authz: RefreshHash 已挂在会话 %q 上——同一 refresh 不得挂两枚会话（登记面亦是防重放面）", cur.ID)
			}
		}
		// 已过期会话或旧代次残留：清残后重试。
		if _, err := r.store.Del(ctx, key); err != nil {
			return fmt.Errorf("authz: 清理过期 refreshHash 索引失败: %w", err)
		}
	}
	return fmt.Errorf("authz: RefreshHash 挂载竞争失败，请重试")
}

// rollbackRegistration 回滚登记失败留下的主键/用户索引（尽力而为，错误聚合）。
//
// 刻意**不删 refresh 索引**：rollback 已不在 refresh 锁内，此时删除可能与并发
// 挂载竞争（误删他人在主键删除后重新挂上的映射）。refresh 索引 TTL 与登记寿命
// 相同，且主键缺失/代次不匹配时 GetByRefreshHash 已按不存在处理、下次
// mountRefresh 会把残留当 stale 清掉——保留它比误删安全。
func (r *StoreRegistry) rollbackRegistration(ctx context.Context, s Session) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	var errs []error
	if _, err := r.store.Del(rctx, r.idKey(s.ID)); err != nil {
		errs = append(errs, fmt.Errorf("回滚会话主键: %w", err))
	}
	if err := r.store.SRem(rctx, r.userKey(s.UserID), s.ID); err != nil {
		errs = append(errs, fmt.Errorf("回滚用户索引: %w", err))
	}
	return errors.Join(errs...)
}

// cleanupAfterKick 尽力清理下线后的索引（调用方持有 ID 锁）：refresh 索引仅在
// **同一登记代次**仍挂载时删除（refresh 锁内比对）；用户索引幂等 SRem。清理
// 失败只记日志——主键已删即下线已生效，索引残留会被读路径过滤/TTL 出清，不得
// 把成功强踢翻成错误。
func (r *StoreRegistry) cleanupAfterKick(ctx context.Context, stored storedSession) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	if stored.Session.RefreshHash != "" {
		r.cleanupRefreshIndex(rctx, stored)
	}
	if err := r.store.SRem(rctx, r.userKey(stored.Session.UserID), stored.Session.ID); err != nil {
		log.CtxWarn(rctx, "强踢后清理用户索引失败", "session_id", stored.Session.ID, logx.ErrKey, err)
	}
}

// cleanupRefreshIndex 在 refresh 锁内按代次删除 refresh 索引；锁被占用或存储
// 故障时跳过（残留索引对读路径不可见，TTL 自然出清）。
func (r *StoreRegistry) cleanupRefreshIndex(ctx context.Context, stored storedSession) {
	release, acquired, err := r.acquireLock(ctx, r.refreshLockKey(stored.Session.RefreshHash))
	if err != nil {
		log.CtxWarn(ctx, "强踢后获取 refresh 索引锁失败，跳过清理", "session_id", stored.Session.ID, logx.ErrKey, err)
		return
	}
	if !acquired {
		return
	}
	defer release()
	key := r.refreshKey(stored.Session.RefreshHash)
	raw, ok, err := r.store.Get(ctx, key)
	if err != nil {
		log.CtxWarn(ctx, "强踢后读取 refresh 索引失败", "session_id", stored.Session.ID, logx.ErrKey, err)
		return
	}
	if !ok {
		return
	}
	cur, err := decodeRefreshMount(raw)
	if err != nil {
		log.CtxWarn(ctx, "强踢后解析 refresh 索引失败（跳过删除）", "session_id", stored.Session.ID, logx.ErrKey, err)
		return
	}
	if cur.ID != stored.Session.ID || cur.Generation != stored.Generation {
		return // 已被并发重建/覆盖：不得误删
	}
	if _, err := r.store.Del(ctx, key); err != nil {
		log.CtxWarn(ctx, "强踢后删除 refresh 索引失败", "session_id", stored.Session.ID, logx.ErrKey, err)
	}
}

// getSession 读主键并解码（不存在 ⇒ live=false）。
func (r *StoreRegistry) getSession(ctx context.Context, id string) (storedSession, bool, error) {
	raw, ok, err := r.store.Get(ctx, r.idKey(id))
	if err != nil {
		return storedSession{}, false, fmt.Errorf("authz: 读取会话 %q 失败: %w", id, err)
	}
	if !ok {
		return storedSession{}, false, nil
	}
	var stored storedSession
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return storedSession{}, false, fmt.Errorf("authz: 会话 %q 数据损坏: %w", id, err)
	}
	return stored, true, nil
}

// newSessionGeneration 生成登记代次（32 hex；crypto/rand 故障显式上抛——代次
// 是 ABA 判定身份，不可降级成空串/固定值）。
func newSessionGeneration() (string, error) {
	gen, err := uidgen.RandomHexE(16)
	if err != nil {
		return "", fmt.Errorf("authz: 生成会话登记代次失败: %w", err)
	}
	return gen, nil
}

// encodeRefreshMount / decodeRefreshMount 是 refresh 索引值的内部编解码。
func encodeRefreshMount(m refreshMount) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeRefreshMount(raw string) (refreshMount, error) {
	var m refreshMount
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return refreshMount{}, err
	}
	if m.ID == "" || m.Generation == "" {
		return refreshMount{}, fmt.Errorf("refreshMount 缺 ID/Generation")
	}
	return m, nil
}

// acquireLock 抢操作锁：返回释放函数；acquired=false 表示锁已被占用。
// 释放失败只记日志（锁 TTL 自愈），不改变调用方已落地结果。
func (r *StoreRegistry) acquireLock(ctx context.Context, key string) (release func(), acquired bool, err error) {
	ok, err := r.store.SetNX(ctx, key, "1", sessionOpLockTTL)
	if err != nil {
		return nil, false, fmt.Errorf("authz: 获取会话操作锁失败: %w", err)
	}
	if !ok {
		return nil, false, nil
	}
	return func() { r.releaseLock(ctx, key) }, true, nil
}

// releaseLock 尽力删除操作锁（调用方上下文可能已取消，用脱离取消的短超时上下文）。
func (r *StoreRegistry) releaseLock(ctx context.Context, key string) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	if _, err := r.store.Del(rctx, key); err != nil {
		log.CtxWarn(rctx, "会话操作锁释放失败（等待 TTL 自然过期）", "key", key, logx.ErrKey, err)
	}
}

// normalizeStorePrefix 规范化键前缀（空串回退缺省；非空补尾部冒号）。
func normalizeStorePrefix(prefix string) string {
	if prefix == "" {
		return defaultStorePrefix
	}
	if strings.HasSuffix(prefix, ":") {
		return prefix
	}
	return prefix + ":"
}

func (r *StoreRegistry) idKey(id string) string            { return r.prefix + "id:" + id }
func (r *StoreRegistry) refreshKey(hash string) string     { return r.prefix + "refresh:" + hash }
func (r *StoreRegistry) userKey(userID string) string      { return r.prefix + "user:" + userID }
func (r *StoreRegistry) idLockKey(id string) string        { return r.prefix + "lock:id:" + id }
func (r *StoreRegistry) refreshLockKey(hash string) string { return r.prefix + "lock:refresh:" + hash }
