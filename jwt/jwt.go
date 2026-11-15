// Package jwt 提供 JWT 签发与校验，覆盖两种主流形态：RS256（非对称密钥对，
// Sign/Parse）与 HS256（对称共享密钥，SymmetricSigner/ParseSymmetric，#86）。
// 两形态之上另有 access+refresh 双令牌对原语（Manager：成对签发 IssuePair、
// 分型校验 ParseTyped、refresh 轮换 Refresh，#97）。
//
// 两形态共享同一套 SignOption/ParseOption/Claims 与校验语义；每个入口固定自己
// 的算法（RS256 入口只认 RS256、HS256 入口只认 HS256），密钥形态绑定算法关死
// alg 混淆。解析侧校验入口：WithAudience（#66）与 WithExpectedIssuer（#95）；
// 解析侧安全缺省：强制 exp（#135，WithAllowNoExpiry 豁免）与 30s leeway（#137，
// WithLeeway 覆盖）；签发侧 aud 出口：WithAudienceClaims（#117）——与
// WithAudience 闭环，库签发的令牌可带 aud，多受众部署不再被迫手搓 payload。
//
// 硬契约（与既有消费方互通，不可改）：
//   - RS256 形态 alg 恰为 RS256；HS256 形态 alg 恰为 HS256
//   - JWT header 缺省只含 {"alg":"<alg>"}，不带 typ；WithKeyID 显式追加 kid
//     （header 收窄为 alg(+kid)）。OIDC id_token 场景必须设置 kid：JWKS 端点
//     可能发布多把密钥，客户端只能靠 header 的 kid 选钥验签
//   - 业务自定义声明平铺进 payload，解析时收集进 Claims.Extra
//
// 多钥轮换解析：Claims.Header 始终是解析令牌的 header 快照（含 kid）；需要
// 按 kid 选钥时用 WithKeyIDResolver（RS256）/ WithSymmetricKeyIDResolver
// （HS256）注入回调，无需调用方自拆 JWT 三段。
package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken 表示令牌无法解析或校验失败。
var ErrInvalidToken = errors.New("jwt: invalid token")

// Claims 是签发与解析的载荷容器。
type Claims struct {
	gojwt.RegisteredClaims
	// Header 是解析令牌的 JWT header 快照（缺省含 alg，WithKeyID 签发时含 kid）。
	// 签发侧产出不经 Claims，本字段只由 Parse/ParseSymmetric/Manager.ParseTyped
	// 填充；每次解析返回独立副本，改写不影响其它解析结果。
	Header map[string]any
	// Extra 承载业务自定义声明（签发时经 WithClaim 平铺进 payload，解析时收集回来）。
	Extra map[string]any
}

// KeyID 返回解析令牌 header 的 kid（缺失或非字符串返回空串）。OIDC/JWKS 多钥
// 场景与 WithKeyIDResolver 同源，便于调用方在验签后读回本次选中的密钥 ID。
func (c *Claims) KeyID() string {
	if c == nil || c.Header == nil {
		return ""
	}
	kid, _ := c.Header["kid"].(string)
	return kid
}

// signOptions 是签发选项的内部表示。
type signOptions struct {
	issuer    string
	subject   string
	jti       string
	keyID     string
	audience  []string
	ttl       time.Duration
	noExpiry  bool
	notBefore *time.Time
	claims    map[string]any
	nowFn     func() time.Time
	tokenType string
}

// SignOption 是 Sign 的函数选项。
type SignOption func(*signOptions)

// WithIssuer 设置 iss。
func WithIssuer(iss string) SignOption { return func(o *signOptions) { o.issuer = iss } }

// WithSubject 设置 sub。
func WithSubject(sub string) SignOption { return func(o *signOptions) { o.subject = sub } }

// WithAudienceClaims 设置 aud（受众）（#117）：单受众写 string 形态、多受众写
// []string 形态，与 claimsFromMap 的解析面（string/数组双收）对称（RFC 7519
// §4.1.3 双形态）。不设置时令牌不带 aud（向后兼容）；零参与不设置同效（显式
// 回退默认值）；受众含空串直接 panic——空受众是配置零值透传的最常见形态，签出
// 的令牌在 WithAudience（#66）fail-closed 校验下永不匹配，静默接受等于批量产出
// 必被拒的令牌（WithTTL(0) panic（#65）同款纪律）。重复调用 last-wins（与
// WithIssuer 等注册声明选项同口径）。入参即刻 slices.Clone 拷贝，调用方事后
// 改写原切片不影响签发结果。
//
// 名字不是 WithAudience：解析侧已有 WithAudience(...string) ParseOption（校验
// 期望受众），Go 不允许同名重载，此处取「写入 aud 声明」语义与之分型（与
// WithExpectedIssuer（#95）同款命名分型纪律）。aud 是保留声明（reservedClaims），
// 不可经 WithClaim 注入（#71）——本选项是 aud 的唯一签发出口。
func WithAudienceClaims(aud ...string) SignOption {
	return func(o *signOptions) {
		for _, a := range aud {
			if a == "" {
				panic("jwt: WithAudienceClaims 的受众不能是空串——空受众是配置零值透传的最常见形态，签出的令牌在 WithAudience（#66）fail-closed 校验下永不匹配（#117）")
			}
		}
		o.audience = slices.Clone(aud)
	}
}

// WithJTI 设置 jti（令牌 ID）。
func WithJTI(jti string) SignOption { return func(o *signOptions) { o.jti = jti } }

// WithKeyID 设置 JWT header 的 kid（密钥 ID，#195）：header 从「只含 alg」
// 窄契约扩展为 alg(+kid)，仍不带 typ；kid 不参与签名内容，无安全面变化。
//
// OIDC id_token / JWKS 多密钥场景必须设置 kid——客户端按 header 的 kid 从
// JWKS 选择验签公钥。空串表示不写 kid（显式回退默认值，header 维持只含
// alg）；RS256 与 HS256（SymmetricSigner.Sign）共用同一 SignOption 面。
func WithKeyID(kid string) SignOption { return func(o *signOptions) { o.keyID = kid } }

// WithTTL 设置 exp = iat + ttl。d 为 0 直接 panic（#65）：显式 0 与「未设置」
// 不可区分，而最可能的成因是「配置缺失的零值透传」——静默接受等于放行一批
// 永不过期的凭据，与 uidgen.RandomHex 拒绝空串密钥（#50）同款纪律。确需无
// 过期令牌请显式 WithNoExpiry。负值不拦（既有消费方用负 ttl 构造已过期令牌
// 做校验测试）。
func WithTTL(d time.Duration) SignOption {
	return func(o *signOptions) {
		if d == 0 {
			panic("jwt: WithTTL(0)——永不过期令牌是最危险的缺省（多为配置零值透传），确需无过期令牌请显式 WithNoExpiry()（#65）")
		}
		o.ttl = d
		o.noExpiry = false // last-wins：WithNoExpiry 之后再 WithTTL 恢复写 exp
	}
}

// WithNoExpiry 显式签发无 exp 的令牌（#65）：名字本身即审计信号，grep 得到。
// 无 exp 令牌一旦泄漏没有自然失效路径，仅供确有轮换/吊销机制的场景；与
// WithTTL 并用时后应用的生效。
func WithNoExpiry() SignOption { return func(o *signOptions) { o.noExpiry = true } }

// WithNotBefore 设置 nbf。
func WithNotBefore(t time.Time) SignOption { return func(o *signOptions) { o.notBefore = &t } }

// WithNow 注入签发时钟：iat = now()、exp = iat + ttl 同钟源（nbf 仍取
// WithNotBefore 的绝对时刻）。缺省 time.Now（#64：缺省行为不变）；f 为 nil
// 直接 panic——静默回落真实时钟会让 iat 无声漂移。测试可注入假时钟获得
// 确定性令牌，不再只能断言 iat≈now 的区间。
func WithNow(f func() time.Time) SignOption {
	return func(o *signOptions) {
		if f == nil {
			panic("jwt: WithNow 的时钟函数不能为 nil——静默回落 time.Now() 会让 iat 无声漂移（#64）")
		}
		o.nowFn = f
	}
}

// WithIssuedAt 显式设置签发时刻：iat = t、exp = t + ttl，等价于 WithNow(
// 固定返回 t)。带显式签发时刻的签发面（如消费方 Issue(..., now time.Time)
// 参数形态）委托本包时用它透传 now，缺省行为不变（#64）。
func WithIssuedAt(t time.Time) SignOption {
	return func(o *signOptions) { o.nowFn = func() time.Time { return t } }
}

// reservedClaims 是保留声明名：RFC 7519 §4.1 注册声明 + token_type（#97 双令牌
// 分型保留名）。kitx/jwt 为它们提供专属签发通道（WithIssuer/WithSubject/
// WithAudienceClaims/WithJTI/WithNotBefore；exp/iat 由 WithTTL/WithNoExpiry 与
// 签发时钟派生；token_type 由 Manager 盖章），业务声明不得占用这些键。
var reservedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {}, "jti": {},
	"token_type": {},
}

// WithClaim 追加一个业务自定义声明。
//
// 保留声明（iss/sub/aud/exp/nbf/iat/jti，及 #97 起的双令牌分型名 token_type）
// 不可经 WithClaim 注入，注入时 Sign 直接报错（#71）：Sign 先写保留声明、最后
// 平铺 claims，无条件覆盖会让 WithClaim("exp", ...) 顶掉过期时间、
// WithClaim("iss", externalInput) 篡改签发者、WithClaim("token_type", ...)
// 伪造分型——claim key 若来自配置/请求拼接，就是令牌声明注入面。注册声明请用
// WithIssuer/WithSubject/WithAudienceClaims/WithJTI/WithNotBefore 设置，
// exp/iat 由 WithTTL 与签发时钟派生，token_type 由 Manager（#97）盖章。
func WithClaim(key string, val any) SignOption {
	return func(o *signOptions) { o.claims[key] = val }
}

// Sign 用 RS256 签发令牌。缺省 iat = time.Now()、ttl = 24h；可用 WithNow/
// WithIssuedAt 注入签发时刻（iat 与 exp 同钟源），WithNoExpiry 显式去掉 exp。
// 对称形态（HS256 共享密钥）见 SymmetricSigner（#86）。
func Sign(kp *KeyPair, opts ...SignOption) (string, error) {
	if kp == nil || kp.Private == nil {
		return "", fmt.Errorf("%w: 缺少私钥", ErrInvalidToken)
	}
	payload, header, err := signParts("RS256", opts)
	if err != nil {
		return "", err
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims(payload))
	tok.Header = header
	return tok.SignedString(kp.Private)
}

// signParts 应用签发选项并组装 payload 与 header（#86：RS256/HS256 两形态共用
// 同一份签发语义——缺省 ttl=24h、iat/exp 同钟源派生、注册声明注入面防护 #71；
// #195 header 缺省只含 alg，WithKeyID 显式追加 kid）。
func signParts(alg string, opts []SignOption) (map[string]any, map[string]any, error) {
	o := &signOptions{ttl: 24 * time.Hour, claims: map[string]any{}, nowFn: time.Now}
	for _, opt := range opts {
		opt(o)
	}
	// 保留声明注入面 fail-closed（#71）：claims 平铺在保留声明写入之后、
	// 无条件覆盖，注入保留键 = 顶掉 exp/iss/iat 等的既定值（#97 起 token_type
	// 同样保留——伪造分型即分型混淆注入面）。
	if hits := reservedClaimHits(o.claims); len(hits) > 0 {
		return nil, nil, fmt.Errorf("%w: WithClaim 不能注入保留声明 %v（#71）——这是令牌声明注入面；注册声明请用 WithIssuer/WithSubject/WithAudienceClaims/WithJTI/WithNotBefore 设置，exp/iat 由 WithTTL 与签发时钟派生，token_type 由 Manager 盖章（#97）", ErrInvalidToken, hits)
	}
	now := o.nowFn()
	payload := map[string]any{}
	if o.issuer != "" {
		payload["iss"] = o.issuer
	}
	if o.subject != "" {
		payload["sub"] = o.subject
	}
	// aud 双形态（#117）：单受众 string、多受众 []string——与 claimsFromMap
	// 的解析面对称（RFC 7519 §4.1.3 两形态都合法）。aud 的唯一写入口是
	// WithAudienceClaims；WithClaim("aud") 仍被上面的保留声明防护拒绝（#71
	// 注入面不动）。
	switch len(o.audience) {
	case 0:
	case 1:
		payload["aud"] = o.audience[0]
	default:
		payload["aud"] = o.audience
	}
	if o.jti != "" {
		payload["jti"] = o.jti
	}
	if !o.noExpiry {
		payload["exp"] = now.Add(o.ttl).Unix()
	}
	payload["iat"] = now.Unix()
	if o.notBefore != nil {
		payload["nbf"] = o.notBefore.Unix()
	}
	for k, v := range o.claims {
		payload[k] = v
	}
	if o.tokenType != "" {
		// 双令牌分型盖章（#97）：claims 平铺之后无条件写入——业务声明顶不掉，
		// plain Sign（tokenType 为空）保持不带该声明，payload 向后兼容。
		payload["token_type"] = o.tokenType
	}
	// header 窄契约（#195）：无 kid 时仍是单键 map（字节零变化）；有 kid 时
	// 恰追加一个 kid 字段，仍不带 typ。
	header := map[string]any{"alg": alg}
	if o.keyID != "" {
		header["kid"] = o.keyID
	}
	return payload, header, nil
}

// defaultLeeway 是解析校验缺省的时钟偏移容忍（#137）：多实例部署下各实例
// NTP 步进节奏不同，零容忍会让 iat==nbf 的刚签发令牌在偏移实例上被
// ErrTokenNotValidYet 拒一次（401 后客户端重试才恢复，无日志定位点）。取
// 30s——覆盖秒级漂移与常规 NTP 阶跃，又不过分拉长过期令牌的残效窗口（#137
// 建议区间 30s~60s 的安全侧取值）；显式 WithLeeway 可覆盖，WithLeeway(0) 仍是
// 严格零容忍。
const defaultLeeway = 30 * time.Second

// parseOptions 是解析选项的内部表示。
type parseOptions struct {
	leeway        time.Duration
	audience      []string
	issuer        string
	allowNoExpiry bool
	rsaKeyByID    func(kid string) (*rsa.PublicKey, error)
	symKeyByID    func(kid string) ([]byte, error)
}

// ParseOption 是 Parse 的函数选项。
type ParseOption func(*parseOptions)

// WithLeeway 设置时钟偏移容忍（覆盖缺省值）。缺省 30s（#137：跨实例部署的
// 秒级时钟漂移不应把刚签发的令牌拒在门外）；显式传 0 表示严格零容忍。
func WithLeeway(d time.Duration) ParseOption { return func(o *parseOptions) { o.leeway = d } }

// WithAllowNoExpiry 豁免「令牌必须带 exp」的缺省强制（#135）。缺省 Parse/
// ParseSymmetric/Manager.ParseTyped 一律拒绝无 exp 令牌——签发侧「永不过期
// 令牌是最危险的缺省」（WithTTL(0) panic，#65）的解析侧闭环：golang-jwt v5
// 仅在 exp 存在时校验，无 exp 令牌缺省放行会让 #65 的纪律在消费面单侧失效。
// 只影响 exp 强制，其余校验（签名/nbf/aud/iss）不变。确有消费无 exp 令牌的
// 场景（签发侧 WithNoExpiry 的对偶）请显式豁免——名字即审计信号，grep 得到。
func WithAllowNoExpiry() ParseOption { return func(o *parseOptions) { o.allowNoExpiry = true } }

// WithAudience 设置期望受众（#66）：令牌 aud 命中任一即通过；令牌无 aud 时
// 拒绝（fail-closed）。不设置时不校验 aud（向后兼容）——签名校验只证明
// 「是我的 key 签的」，不证明「是签给我的」；同密钥多受众场景必须显式配置。
func WithAudience(expected ...string) ParseOption {
	return func(o *parseOptions) { o.audience = expected }
}

// WithExpectedIssuer 设置期望签发者（#95）：令牌 iss 必须与之严格相等才通过；
// 令牌无 iss 或 iss 不匹配 ⇒ 拒绝（fail-closed）。不设置时不校验 iss（向后
// 兼容）——与 WithAudience 同一口径：签名校验只证明「是我的 key 签的」，不
// 证明「是约定的签发方签的」；共享密钥（HS256）多签发方场景下，任意持钥方
// 都能签出 iss 为任意值的令牌，必须显式钉住来源。
//
// 名字不是 WithIssuer：签发侧已有 WithIssuer(iss) SignOption（写入 iss），
// Go 不允许同名重载；解析侧取「期望」语义与 WithAudience（期望受众）对称。
// 上游 golang-jwt 的校验是严格相等 + iss 必须存在（缺失报
// ErrTokenRequiredClaimMissing、不匹配报 ErrTokenInvalidIssuer、类型异常报
// ErrTokenUnverifiable，均可经错误链 errors.Is，#70）。
func WithExpectedIssuer(expected string) ParseOption {
	return func(o *parseOptions) { o.issuer = expected }
}

// WithKeyIDResolver 设置 RS256 按 header kid 选公钥的回调（#195）：多钥轮换/
// JWKS 场景下调用方不再需要自拆 token 取 kid，公钥选择与验签在同一解析调用中
// 完成。配置后 Parse 的 pub 参数可为 nil（resolver 优先于静态公钥）；header 缺
// kid、kid 非字符串/空串、回调返回 (nil, nil) 或 error 一律 fail-closed（错误
// 链保留回调原因，外层仍可 errors.Is(ErrInvalidToken)）。
//
// 未配置本选项时行为与既有 Parse 完全一致（pub 必填、header 不参与选钥）；
// 解析成功后 header 快照在 Claims.Header，kid 可经 Claims.KeyID 读取。
func WithKeyIDResolver(resolve func(kid string) (*rsa.PublicKey, error)) ParseOption {
	return func(o *parseOptions) { o.rsaKeyByID = resolve }
}

// WithSymmetricKeyIDResolver 设置 HS256 按 header kid 选共享密钥的回调（#195
// 的 HS256 对偶）：配置后 ParseSymmetric 的 secret 参数可为 nil（resolver 优先），
// 密钥环中每把密钥仍须满足 ≥32 字节（RFC 7518 §3.2）；回调返回的密钥过弱时
// 解析拒绝（与 NewSymmetric 同一判据）。其余 fail-closed 语义同 WithKeyIDResolver。
func WithSymmetricKeyIDResolver(resolve func(kid string) ([]byte, error)) ParseOption {
	return func(o *parseOptions) { o.symKeyByID = resolve }
}

// Parse 校验并解析令牌（RS256-only，不校验 aud/iss）。对称形态（HS256 共享
// 密钥）见 ParseSymmetric（#86）——两入口共享校验语义。
//
// 安全缺省（与签发侧纪律闭环）：
//   - 强制 exp（#135）：无 exp 令牌一律拒绝——「永不过期令牌是最危险的缺省」
//     （签发侧 WithTTL(0) panic，#65）在解析侧不能单侧失效；确有消费无 exp
//     令牌的场景显式 WithAllowNoExpiry 豁免（对偶签发侧 WithNoExpiry）；
//   - 缺省 leeway 30s（#137）：跨实例部署的秒级时钟漂移不应把刚签发的令牌
//     拒在门外；WithLeeway 可覆盖（显式 0 = 严格零容忍）。
//
// 错误链保留（#70）：失败时外层哨兵 ErrInvalidToken 与 gojwt 底层 sentinel
// （ErrTokenExpired/ErrTokenSignatureInvalid/ErrTokenNotValidYet 等）同时可
// errors.Is——业务侧可据此分流「过期→走刷新、签名坏→踢下线」。缺 exp 报
// ErrTokenRequiredClaimMissing，同样可 errors.Is。
//
// 已注册声明（iss/sub/aud/jti/exp/iat/nbf）收进 RegisteredClaims；其余进 Extra。
// iss/sub/jti 存在但非字符串时拒绝（#67）：RFC 7519 §4.1.1/§4.1.2 要求 iss/sub
// MUST be a String，类型异常即规格违规令牌，fail-closed 而非静默归零放行
// （golang-jwt 上游 MapClaims.GetSubject 对类型异常同样返回错误）；声明缺失
// 维持零值不报错（exp 除外，见上）——缺失声明的令牌按消费方自身的校验责任走。
func Parse(token string, pub *rsa.PublicKey, opts ...ParseOption) (*Claims, error) {
	o := &parseOptions{leeway: defaultLeeway}
	for _, opt := range opts {
		opt(o)
	}
	if o.symKeyByID != nil {
		return nil, fmt.Errorf("%w: WithSymmetricKeyIDResolver 只适用于 HS256 入口 ParseSymmetric（RS256 请用 WithKeyIDResolver）", ErrInvalidToken)
	}
	if pub == nil && o.rsaKeyByID == nil {
		return nil, fmt.Errorf("%w: 缺少公钥", ErrInvalidToken)
	}
	tok, err := newParser(o, "RS256").Parse(token, func(t *gojwt.Token) (any, error) {
		if o.rsaKeyByID != nil {
			kid, err := headerKeyID(t.Header)
			if err != nil {
				return nil, err
			}
			key, err := o.rsaKeyByID(kid)
			if err != nil {
				return nil, fmt.Errorf("按 kid %q 选公钥: %w", kid, err)
			}
			if key == nil {
				return nil, fmt.Errorf("按 kid %q 选公钥返回 nil", kid)
			}
			return key, nil
		}
		return pub, nil
	})
	if err != nil {
		// 双 %w 保留底层错误链（#70）：外层可 Is 到 ErrInvalidToken，同时
		// gojwt 的 ErrTokenExpired/ErrTokenSignatureInvalid 等 sentinel 也
		// 可 Is——业务侧「过期→走刷新、签名坏→踢下线」的分流依赖它。%v 会
		// 把链拍平成纯文本，两类令牌不可区分。
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	return claimsFromToken(tok)
}

// newParser 构造解析器（#86：入口绑定算法——单算法 WithValidMethods 白名单，
// RS256 入口只认 RS256、HS256 入口只认 HS256，密钥形态绑定算法关死 alg 混淆；
// #135 缺省 WithExpirationRequired 强制 exp，WithAllowNoExpiry 显式豁免）。
func newParser(o *parseOptions, alg string) *gojwt.Parser {
	parserOpts := []gojwt.ParserOption{
		gojwt.WithValidMethods([]string{alg}),
		gojwt.WithLeeway(o.leeway),
	}
	if !o.allowNoExpiry {
		parserOpts = append(parserOpts, gojwt.WithExpirationRequired())
	}
	if len(o.audience) > 0 {
		parserOpts = append(parserOpts, gojwt.WithAudience(o.audience...))
	}
	if o.issuer != "" {
		parserOpts = append(parserOpts, gojwt.WithIssuer(o.issuer))
	}
	return gojwt.NewParser(parserOpts...)
}

// claimsFromToken 把解析产物收进 Claims：载荷交给 claimsFromMap，header 快照
// 收进 Claims.Header（#195：kid/alg 等 header 字段解析后可直接读取）。
func claimsFromToken(tok *gojwt.Token) (*Claims, error) {
	mc, ok := tok.Claims.(gojwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: 载荷类型异常", ErrInvalidToken)
	}
	out, err := claimsFromMap(mc)
	if err != nil {
		return nil, err
	}
	out.Header = cloneHeader(tok.Header)
	return out, nil
}

// cloneHeader 拷贝 header 快照（每次解析独立，调用方改写不影响其它结果）。
func cloneHeader(h map[string]any) map[string]any {
	if h == nil {
		return nil
	}
	out := make(map[string]any, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

// headerKeyID 取 header 的 kid 并 fail-closed 校验（#195 resolver 选钥前置：
// 缺失/空串/非字符串都拒绝——静默回落某把默认密钥会让多钥轮换失去意义）。
func headerKeyID(header map[string]any) (string, error) {
	v, ok := header["kid"]
	if !ok {
		return "", fmt.Errorf("header 缺少 kid，无法按密钥 ID 选钥")
	}
	kid, ok := v.(string)
	if !ok || kid == "" {
		return "", fmt.Errorf("header kid 类型异常或为空: %T", v)
	}
	return kid, nil
}

// claimsFromMap 把 MapClaims 收进 Claims（#86：RS256/HS256 两入口共享同一份
// claims 收集与类型校验语义——#67 类型异常 fail-closed、#70 错误链对两形态同效）。
func claimsFromMap(mc gojwt.MapClaims) (*Claims, error) {
	iss, err := mustStr(mc, "iss")
	if err != nil {
		return nil, err
	}
	sub, err := mustStr(mc, "sub")
	if err != nil {
		return nil, err
	}
	jti, err := mustStr(mc, "jti")
	if err != nil {
		return nil, err
	}
	out := &Claims{Extra: map[string]any{}}
	out.RegisteredClaims = gojwt.RegisteredClaims{
		Issuer:    iss,
		Subject:   sub,
		ID:        jti,
		ExpiresAt: mapTime(mc, "exp"),
		IssuedAt:  mapTime(mc, "iat"),
		NotBefore: mapTime(mc, "nbf"),
	}
	if aud, ok := mc["aud"]; ok {
		if s, ok := aud.(string); ok {
			out.Audience = gojwt.ClaimStrings{s}
		} else {
			out.Audience = gojwt.ClaimStrings{}
			if arr, ok := aud.([]any); ok {
				for _, a := range arr {
					if s, ok := a.(string); ok {
						out.Audience = append(out.Audience, s)
					}
				}
			}
		}
	}
	for k, v := range mc {
		switch k {
		case "iss", "sub", "jti", "exp", "iat", "nbf", "aud":
		default:
			out.Extra[k] = v
		}
	}
	return out, nil
}

// mustStr 取 string 声明并统一做 ErrInvalidToken 包装（#134：claimsFromMap 的
// iss/sub/jti 三段同构错误包装收敛单点；双 %w 与 #70 口径一致——外层可 Is 到
// ErrInvalidToken，内层类型异常错误链也保留）。
func mustStr(mc gojwt.MapClaims, key string) (string, error) {
	s, err := mapStr(mc, key)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	return s, nil
}

// mapStr 取 string 声明（#67）：缺失返回 ("", nil)——缺失按消费方自身的校验
// 责任走，不报错；存在但非字符串返回错误（带声明名与实际类型，如
// 「声明 sub 类型异常: float64」）——数值 sub（部分第三方 provider 与 Java 侧
// Long 序列化产物）静默归零成空 Subject 放行，比拒绝更危险。
func mapStr(mc gojwt.MapClaims, key string) (string, error) {
	v, ok := mc[key]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("声明 %s 类型异常: %T", key, v)
	}
	return s, nil
}

// reservedClaimHits 返回 claims 里命中注册声明名的键（排序，报错文案确定）。
func reservedClaimHits(claims map[string]any) []string {
	var hits []string
	for k := range claims {
		if _, ok := reservedClaims[k]; ok {
			hits = append(hits, k)
		}
	}
	slices.Sort(hits)
	return hits
}

// mapTime 取数字时间声明（缺失、类型异常或值为 0 返回 nil）。
//
// 零值视作「无此声明」（#149）：与上游 golang-jwt parseNumericDate 口径对齐——
// JSON 数字 0（如 "exp":0）是占位缺省，不是「1970 纪元」。缺省强制 exp（#135）
// 时 exp=0 的令牌同样被上游按「无 exp」拒绝；WithAllowNoExpiry 豁免放行后
// Claims.ExpiresAt 必须与库自身判定同向（nil），否则消费方惯用的
// 「ExpiresAt != nil 即已过期」判据在这类令牌上被反转成「1970 年就过期」。
// exp/iat/nbf 共用本函数，三个声明的零值同口径。
func mapTime(mc gojwt.MapClaims, key string) *gojwt.NumericDate {
	v, ok := mc[key]
	if !ok {
		return nil
	}
	switch n := v.(type) {
	case float64:
		if n == 0 {
			return nil
		}
		return gojwt.NewNumericDate(time.Unix(int64(n), 0))
	case int64:
		if n == 0 {
			return nil
		}
		return gojwt.NewNumericDate(time.Unix(n, 0))
	default:
		return nil
	}
}
