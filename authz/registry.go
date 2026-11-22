package authz

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/oekit/authx/uidgen"
	"github.com/oekit/logx"
	"github.com/oekit/pkg/contextx"
	bizerrors "github.com/oekit/pkg/errors"
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

// indexMount 是 refresh/jti 两族索引的公共值形态：会话 ID + 登记代次（#226
// 合并——原 refreshMount/jtiMount 逐字段同构，编解码与挂载骨架随之一并单源）。
// 代次用于清理期 ABA 复核（同 ID 重建后旧索引不得误删新挂载）。两族索引的
// wire 格式本就逐字相同（{"id","generation"}），合并不影响存量数据。
type indexMount struct {
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
//	<prefix>refresh:<refreshHash>  refresh 反查/唯一挂载（indexMount JSON）
//	<prefix>jti:<jti>              access/refresh jti 反查（indexMount JSON，#218）
//	<prefix>user:<userID>          用户索引集合（成员=sessionID）
//	<prefix>all                    全量会话索引集合（成员=sessionID，#218）
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
		return nil, bizerrors.New("authz: NewStoreRegistry 需要非 nil Revoker——Kick/KickUser 的双 hash 拉黑经它落地")
	}
	if store == nil {
		return nil, bizerrors.New("authz: NewStoreRegistry 需要非 nil SessionStore")
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
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.ID == "" || s.UserID == "" || s.RefreshHash == "" {
		return bizerrors.New("authz: Register 的 ID/UserID/RefreshHash 必填（ID=登记主键、RefreshHash=轮换认领键）")
	}
	if ttl <= 0 {
		return bizerrors.Newf("authz: Register 的 ttl 必须为正（got %v）——ttl 是 refresh 剩余寿命，零值透传等于登记长生会话（#65 同款纪律）", ttl)
	}
	release, acquired, err := r.acquireLock(ctx, r.idLockKey(s.ID))
	if err != nil {
		return err
	}
	if !acquired {
		return bizerrors.Newf("authz: 会话 ID %q 正在登记/强踢中，请稍后重试", s.ID)
	}
	defer release()

	gen, err := newSessionGeneration()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(storedSession{Session: s, Generation: gen})
	if err != nil {
		return bizerrors.Wrapf(err, "authz: 会话序列化失败")
	}
	// 主键 SetNX 是「登记不可覆盖」的拍板点（ID 锁之外的第二道原子闸）。
	ok, err := r.store.SetNX(ctx, r.idKey(s.ID), string(payload), ttl)
	if err != nil {
		return bizerrors.Wrapf(err, "authz: 登记会话主键失败")
	}
	if !ok {
		return bizerrors.Newf("authz: 会话 ID %q 已登记——登记不可覆盖，先 Kick 再登记", s.ID)
	}
	if err := r.mountRefresh(ctx, s.ID, s.RefreshHash, gen, ttl); err != nil {
		return errors.Join(err, r.rollbackRegistration(ctx, s, gen))
	}
	// jti 索引（#218）：access/refresh 两枚 jti 都挂，管理端可按任一 jti 反查。
	if err := r.mountJTIs(ctx, s, gen, ttl); err != nil {
		return errors.Join(err, r.rollbackRegistration(ctx, s, gen))
	}
	// 用户索引集合 TTL 只延长不缩短（SAdd 契约）：短寿命会话不得提前抹掉
	// 同用户的长寿命会话。
	if err := r.store.SAdd(ctx, r.userKey(s.UserID), s.ID, ttl); err != nil {
		return errors.Join(bizerrors.Wrapf(err, "authz: 登记用户索引失败"), r.rollbackRegistration(ctx, s, gen))
	}
	// 全量索引（#218，管理端 ListAll）：与用户索引同款 TTL 只延长不缩短。
	if err := r.store.SAdd(ctx, r.allKey(), s.ID, ttl); err != nil {
		return errors.Join(bizerrors.Wrapf(err, "authz: 登记全量索引失败"), r.rollbackRegistration(ctx, s, gen))
	}
	return nil
}

// GetByRefreshHash 按 refresh 哈希查会话（契约见 SessionRegistry）。
func (r *StoreRegistry) GetByRefreshHash(ctx context.Context, refreshHash string) (Session, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	raw, ok, err := r.store.Get(ctx, r.refreshKey(refreshHash))
	if err != nil {
		return Session{}, bizerrors.Wrapf(err, "authz: 查询 refreshHash 索引失败")
	}
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	mount, err := decodeMount(raw)
	if err != nil {
		return Session{}, bizerrors.Wrapf(err, "authz: refreshHash 索引数据损坏")
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

// GetByID 按会话 ID 直查（契约见 SessionRegistry）。
func (r *StoreRegistry) GetByID(ctx context.Context, id string) (Session, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	if id == "" {
		return Session{}, ErrSessionNotFound
	}
	stored, live, err := r.getSession(ctx, id)
	if err != nil {
		return Session{}, err
	}
	if !live {
		return Session{}, ErrSessionNotFound
	}
	return stored.Session, nil
}

// GetByJTI 按 access/refresh jti 反查会话（契约见 SessionRegistry）。
func (r *StoreRegistry) GetByJTI(ctx context.Context, jti string) (Session, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	if jti == "" {
		return Session{}, ErrSessionNotFound
	}
	raw, ok, err := r.store.Get(ctx, r.jtiKey(jti))
	if err != nil {
		return Session{}, bizerrors.Wrapf(err, "authz: 查询 jti 索引失败")
	}
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	mount, err := decodeMount(raw)
	if err != nil {
		return Session{}, bizerrors.Wrapf(err, "authz: jti 索引数据损坏")
	}
	stored, live, err := r.getSession(ctx, mount.ID)
	if err != nil {
		return Session{}, err
	}
	if !live {
		// 索引残留（主键已过期/被删）：语义等同不在；残留由 TTL/清理出清。
		return Session{}, ErrSessionNotFound
	}
	// 代次 + jti 归属复核（#136 ABA 同构）：索引必须指向当前登记、且该 jti
	// 确实是本会话两枚 jti 之一。
	if stored.Generation != mount.Generation || stored.Session.ID != mount.ID {
		return Session{}, ErrSessionNotFound
	}
	if stored.Session.AccessJTI != jti && stored.Session.RefreshJTI != jti {
		return Session{}, ErrSessionNotFound
	}
	return stored.Session, nil
}

// ListByUser 枚举某用户的在线会话（契约见 SessionRegistry）。
func (r *StoreRegistry) ListByUser(ctx context.Context, userID string) ([]Session, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	members, err := r.store.SMembers(ctx, r.userKey(userID))
	if err != nil {
		return nil, bizerrors.Wrapf(err, "authz: 枚举用户会话索引失败")
	}
	return r.sessionsFromIDs(ctx, members, func(s Session) bool { return s.UserID == userID })
}

// ListAll 枚举全平台在线会话（契约见 SessionRegistry，#218）。
//
// 升级提示：all 索引是 v0.12.0 新增，升级前登记的**存量会话**不在索引里
// （不 SCAN 全键反推，避免给存储面加全表扫描）。存量会话的轮换/强踢不受
// 影响（refreshHash 索引仍在）；管理端全量枚举只覆盖升级后登记的会话。
func (r *StoreRegistry) ListAll(ctx context.Context) ([]Session, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	members, err := r.store.SMembers(ctx, r.allKey())
	if err != nil {
		return nil, bizerrors.Wrapf(err, "authz: 枚举全量会话索引失败")
	}
	return r.sessionsFromIDs(ctx, members, nil)
}

// sessionsFromIDs 按 ID 集合读快照并稳定排序（ListByUser/ListAll 共用）。
// keep 为 nil 表示不过滤；过期/已下线/索引错挂的成员不出现（快照语义）。
func (r *StoreRegistry) sessionsFromIDs(ctx context.Context, ids []string, keep func(Session) bool) ([]Session, error) {
	out := make([]Session, 0, len(ids))
	for _, id := range ids {
		stored, live, err := r.getSession(ctx, id)
		if err != nil {
			return nil, err
		}
		if !live {
			continue
		}
		if keep != nil && !keep(stored.Session) {
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
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
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
		return false, bizerrors.Wrapf(err, "authz: 读取会话剩余寿命失败")
	}
	idRelease()
	if !ttlOK || remaining <= 0 {
		// 自然过期：不拉黑（令牌本就过期），索引残留由 TTL/下次挂载清理。
		return false, nil
	}

	var errs []error
	if stored.Session.AccessHash != "" {
		if err := r.rev.Revoke(ctx, stored.Session.AccessHash, remaining); err != nil {
			errs = append(errs, bizerrors.Wrapf(err, "拉黑 access"))
		}
	}
	if stored.Session.RefreshHash != "" {
		if err := r.rev.Revoke(ctx, stored.Session.RefreshHash, remaining); err != nil {
			errs = append(errs, bizerrors.Wrapf(err, "拉黑 refresh"))
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
		// 拉黑已完整落地（上方双路 Revoke 全部成功），但登记项仍存活未删。
		// 返回显式哨兵（#236）：调用方必须能区分「本就不在」与「已拉黑但
		// 下线未完成」——后者可重试，按 (false,nil) 处理会让会话幽灵态
		// （管理端枚举得到、refresh 却不可用）静默残留。
		return false, ErrKickContended
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
		return false, bizerrors.Wrapf(err, "authz: 删除会话主键失败（登记保留，可重试）")
	}
	if !deleted {
		return false, nil // 重锁后自然过期：按不存在返回
	}
	r.cleanupIndexes(ctx, stored)
	return true, nil
}

// Delete 仅删除登记与索引（不拉黑，契约见 SessionRegistry）。
//
// 与 Kick 的差异：不调用 Revoker——调用方已通过其他路径完成令牌撤销（如
// OAuth 撤销端点先拉黑令牌），只需把登记下线。ID 锁内读快照 → 删主键 →
// 清理 refresh/用户/全量/jti 索引（同一套 cleanupIndexes，代次复核防 ABA）。
func (r *StoreRegistry) Delete(ctx context.Context, id string) (bool, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if id == "" {
		return false, nil
	}
	release, acquired, err := r.acquireLock(ctx, r.idLockKey(id))
	if err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}
	defer release()
	stored, live, err := r.getSession(ctx, id)
	if err != nil {
		return false, err
	}
	if !live {
		return false, nil
	}
	deleted, err := r.store.Del(ctx, r.idKey(id))
	if err != nil {
		return false, bizerrors.Wrapf(err, "authz: 删除会话主键失败（登记保留，可重试）")
	}
	if !deleted {
		return false, nil
	}
	r.cleanupIndexes(ctx, stored)
	return true, nil
}

// KickUser 强踢某用户全部在线会话（契约见 SessionRegistry）。
func (r *StoreRegistry) KickUser(ctx context.Context, userID string) (int, error) {
	// #231：nil ctx 归一 Background，裸 ctx.Err() 对 nil 接口即 panic。
	ctx = contextx.OrBackground(ctx)
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	members, err := r.store.SMembers(ctx, r.userKey(userID))
	if err != nil {
		return 0, bizerrors.Wrapf(err, "authz: 枚举用户会话索引失败")
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
// 重试一次。骨架与错误文案经 mountIndexUnique 单源（#226 收敛，与 jti 挂载
// 原为逐字同构的两份）；refresh 侧多一层 refresh 锁（挂载/强踢互斥）。
func (r *StoreRegistry) mountRefresh(ctx context.Context, id, refreshHash, gen string, ttl time.Duration) error {
	release, acquired, err := r.acquireLock(ctx, r.refreshLockKey(refreshHash))
	if err != nil {
		return err
	}
	if !acquired {
		return bizerrors.New("authz: refreshHash 索引正在变更（挂载/强踢），请稍后重试")
	}
	defer release()

	value, err := encodeMount(indexMount{ID: id, Generation: gen})
	if err != nil {
		return bizerrors.Wrapf(err, "authz: refreshHash 索引序列化失败")
	}
	return r.mountIndexUnique(ctx, "refreshHash", r.refreshKey(refreshHash), value, ttl,
		func(cur indexMount) error {
			return bizerrors.Newf("authz: RefreshHash 已挂在会话 %q 上——同一 refresh 不得挂两枚会话（登记面亦是防重放面）", cur.ID)
		})
}

// mountIndexUnique 是 mountRefresh/mountJTIs 的共同骨架（#226 收敛）：
// SetNX → 占用则 Get+解码 → 活会话同代次 ⇒ onOccupied（两族占用语义不同：
// refresh 唯一挂载 vs jti 全局唯一，文案由回调注入）；已过期会话/旧代次
// 残留 ⇒ 清残后重试一次。
func (r *StoreRegistry) mountIndexUnique(ctx context.Context, what, key, value string, ttl time.Duration, onOccupied func(cur indexMount) error) error {
	for attempt := 0; attempt < 2; attempt++ {
		ok, err := r.store.SetNX(ctx, key, value, ttl)
		if err != nil {
			return bizerrors.Wrapf(err, "authz: 挂载 %s 索引失败", what)
		}
		if ok {
			return nil
		}
		raw, exists, err := r.store.Get(ctx, key)
		if err != nil {
			return bizerrors.Wrapf(err, "authz: 查询 %s 索引失败", what)
		}
		if exists {
			cur, err := decodeMount(raw)
			if err != nil {
				return bizerrors.Wrapf(err, "authz: %s 索引数据损坏", what)
			}
			stored, live, err := r.getSession(ctx, cur.ID)
			if err != nil {
				return err
			}
			if live && stored.Generation == cur.Generation {
				return onOccupied(cur)
			}
		}
		// 已过期会话或旧代次残留：清残后重试。
		if _, err := r.store.Del(ctx, key); err != nil {
			return bizerrors.Wrapf(err, "authz: 清理过期 %s 索引失败", what)
		}
	}
	return bizerrors.Newf("authz: %s 索引挂载竞争失败，请重试", what)
}

// rollbackRegistration 回滚登记失败留下的主键/用户/全量/jti 索引（尽力而为，
// 错误聚合）。
//
// 刻意**不删 refresh 索引**：rollback 已不在 refresh 锁内，此时删除可能与并发
// 挂载竞争（误删他人在主键删除后重新挂上的映射）。refresh 索引 TTL 与登记寿命
// 相同，且主键缺失/代次不匹配时 GetByRefreshHash 已按不存在处理、下次
// mountRefresh 会把残留当 stale 清掉——保留它比误删安全。jti 索引同理只在
// 代次匹配时删除（jti 全局唯一，不存在并发挂载同一 jti 的合法路径）。
func (r *StoreRegistry) rollbackRegistration(ctx context.Context, s Session, gen string) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	var errs []error
	if _, err := r.store.Del(rctx, r.idKey(s.ID)); err != nil {
		errs = append(errs, bizerrors.Wrapf(err, "回滚会话主键"))
	}
	if err := r.store.SRem(rctx, r.userKey(s.UserID), s.ID); err != nil {
		errs = append(errs, bizerrors.Wrapf(err, "回滚用户索引"))
	}
	if err := r.store.SRem(rctx, r.allKey(), s.ID); err != nil {
		errs = append(errs, bizerrors.Wrapf(err, "回滚全量索引"))
	}
	errs = append(errs, r.cleanupJTIIndexes(rctx, storedSession{Session: s, Generation: gen})...)
	return errors.Join(errs...)
}

// mountJTIs 挂载 access/refresh jti 索引（#218，调用方已持有 ID 锁）。
// jti 全局唯一是签发面不变式：已挂到**同代次**活会话 ⇒ 报错（重复 jti 是
// 严重缺陷，宁可登记失败也不静默覆盖）；挂到已过期会话/旧代次残留 ⇒ 清残后
// 重试一次（与 mountRefresh 同款）。
func (r *StoreRegistry) mountJTIs(ctx context.Context, s Session, gen string, ttl time.Duration) error {
	value, err := encodeMount(indexMount{ID: s.ID, Generation: gen})
	if err != nil {
		return bizerrors.Wrapf(err, "authz: jti 索引序列化失败")
	}
	for _, jti := range []string{s.RefreshJTI, s.AccessJTI} {
		if jti == "" {
			continue
		}
		if err := r.mountIndexUnique(ctx, "jti", r.jtiKey(jti), value, ttl,
			func(cur indexMount) error {
				return bizerrors.Newf("authz: jti %q 已挂在会话 %q 上——jti 必须全局唯一（签发面重复 jti 是严重缺陷）", jti, cur.ID)
			}); err != nil {
			return err
		}
	}
	return nil
}

// cleanupIndexes 尽力清理下线后的索引（Kick/Delete 共用；调用方持有 ID 锁）：
// refresh 索引仅在**同一登记代次**仍挂载时删除（refresh 锁内比对）；jti 索引
// 同样按代次比对后删除；用户/全量索引幂等 SRem。清理失败只记日志——主键已删
// 即下线已生效，索引残留会被读路径过滤/TTL 出清，不得把成功强踢翻成错误。
func (r *StoreRegistry) cleanupIndexes(ctx context.Context, stored storedSession) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	if stored.Session.RefreshHash != "" {
		r.cleanupRefreshIndex(rctx, stored)
	}
	if err := r.store.SRem(rctx, r.userKey(stored.Session.UserID), stored.Session.ID); err != nil {
		log.CtxWarn(rctx, "下线后清理用户索引失败", "session_id", stored.Session.ID, logx.ErrKey, err)
	}
	if err := r.store.SRem(rctx, r.allKey(), stored.Session.ID); err != nil {
		log.CtxWarn(rctx, "下线后清理全量索引失败", "session_id", stored.Session.ID, logx.ErrKey, err)
	}
	for _, err := range r.cleanupJTIIndexes(rctx, stored) {
		log.CtxWarn(rctx, "下线后清理 jti 索引失败", "session_id", stored.Session.ID, logx.ErrKey, err)
	}
}

// cleanupJTIIndexes 按代次删除会话的两枚 jti 索引（调用方持 ID 锁）。
// 索引已被并发重建/覆盖（ID 或代次不匹配）⇒ 跳过，不得误删（#136 ABA 同构）。
func (r *StoreRegistry) cleanupJTIIndexes(ctx context.Context, stored storedSession) []error {
	var errs []error
	for _, jti := range []string{stored.Session.RefreshJTI, stored.Session.AccessJTI} {
		if jti == "" {
			continue
		}
		key := r.jtiKey(jti)
		raw, ok, err := r.store.Get(ctx, key)
		if err != nil {
			errs = append(errs, bizerrors.Wrapf(err, "读取 jti 索引 %q", jti))
			continue
		}
		if !ok {
			continue
		}
		mount, err := decodeMount(raw)
		if err != nil {
			errs = append(errs, bizerrors.Wrapf(err, "解析 jti 索引 %q", jti))
			continue
		}
		if mount.ID != stored.Session.ID || mount.Generation != stored.Generation {
			continue
		}
		if _, err := r.store.Del(ctx, key); err != nil {
			errs = append(errs, bizerrors.Wrapf(err, "删除 jti 索引 %q", jti))
		}
	}
	return errs
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
	cur, err := decodeMount(raw)
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
		return storedSession{}, false, bizerrors.Wrapf(err, "authz: 读取会话 %q 失败", id)
	}
	if !ok {
		return storedSession{}, false, nil
	}
	var stored storedSession
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return storedSession{}, false, bizerrors.Wrapf(err, "authz: 会话 %q 数据损坏", id)
	}
	return stored, true, nil
}

// newSessionGeneration 生成登记代次（32 hex；crypto/rand 故障显式上抛——代次
// 是 ABA 判定身份，不可降级成空串/固定值）。
func newSessionGeneration() (string, error) {
	gen, err := uidgen.RandomHexE(16)
	if err != nil {
		return "", bizerrors.Wrapf(err, "authz: 生成会话登记代次失败")
	}
	return gen, nil
}

// encodeMount / decodeMount 是 refresh/jti 索引值的公共编解码（#226 合并，
// 原为两份除错误文案外逐字重复的实现）。
func encodeMount(m indexMount) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeMount(raw string) (indexMount, error) {
	var m indexMount
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return indexMount{}, err
	}
	if m.ID == "" || m.Generation == "" {
		return indexMount{}, bizerrors.New("indexMount 缺 ID/Generation")
	}
	return m, nil
}

// acquireLock 抢操作锁：返回释放函数；acquired=false 表示锁已被占用。
// 释放失败只记日志（锁 TTL 自愈），不改变调用方已落地结果。
func (r *StoreRegistry) acquireLock(ctx context.Context, key string) (release func(), acquired bool, err error) {
	ok, err := r.store.SetNX(ctx, key, "1", sessionOpLockTTL)
	if err != nil {
		return nil, false, bizerrors.Wrapf(err, "authz: 获取会话操作锁失败")
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
func (r *StoreRegistry) jtiKey(jti string) string          { return r.prefix + "jti:" + jti }
func (r *StoreRegistry) allKey() string                    { return r.prefix + "all" }
func (r *StoreRegistry) userKey(userID string) string      { return r.prefix + "user:" + userID }
func (r *StoreRegistry) idLockKey(id string) string        { return r.prefix + "lock:id:" + id }
func (r *StoreRegistry) refreshLockKey(hash string) string { return r.prefix + "lock:refresh:" + hash }
