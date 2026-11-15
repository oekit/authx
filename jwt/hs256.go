// HS256 对称形态（#86）：与 RS256（jwt.go）并列的第二种主流 JWT 形态——共享密钥
// HMAC。内网 SSO / 网关注入 / 服务间对等约定场景没有证书分发问题，IdP 与资源服务
// 约定一个 secret 即可；此前该场景下游各自手搓三段式解析 + HMAC 校验 + claims
// 校验（alg 混淆、hmac.Equal 常量时间比较、aud 双形态解析等坑每份实现各踩一遍），
// 库侧一份正确实现收编整个面。
package jwt

import (
	"fmt"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// hs256SecretMinLen 是 HS256 共享密钥的最小长度（字节）。RFC 7518 §3.2 要求密钥
// 长度 ≥ 哈希输出大小（HS256 = 256 bit = 32 字节）——弱密钥让 HMAC 的安全上限
// 跌到密钥熵，缺省密钥/占位符 secret（env 漏配、"secret" 之类）是暴力破解软肋。
const hs256SecretMinLen = 32

// SymmetricSigner 持有 HS256 共享密钥的签发器（对称形态，与 KeyPair/RS256 并列）。
// 签发选项与 RS256 形态同一套 SignOption，签发语义完全一致（#86）。
type SymmetricSigner struct {
	secret []byte
}

// NewSymmetric 用共享密钥构造 HS256 签发器。
//
// secret 缺失或长度 < 32 字节（RFC 7518 §3.2 下限）直接报错 fail-fast（#86）：
// 与全仓「配置错误宁可启动即暴露」哲学一致，不能等到首个令牌校验时才见分晓，
// 也不设「静默接受短密钥」的兼容路径。
func NewSymmetric(secret []byte) (*SymmetricSigner, error) {
	if err := checkSecret(secret); err != nil {
		return nil, err
	}
	// 拷贝一份，防调用方后续原地改写共享底层数组。
	return &SymmetricSigner{secret: append([]byte(nil), secret...)}, nil
}

// checkSecret 校验共享密钥强度（NewSymmetric 构造期与 ParseSymmetric 同一判据）。
func checkSecret(secret []byte) error {
	if len(secret) < hs256SecretMinLen {
		return fmt.Errorf("HS256 共享密钥缺失或过弱（%d 字节 < 下限 %d 字节，RFC 7518 §3.2）——弱 HMAC 密钥 fail-fast 不做静默兼容（#86）", len(secret), hs256SecretMinLen)
	}
	return nil
}

// Sign 用 HS256 签发令牌：选项与签发语义（缺省 ttl=24h、iat/exp 同钟源、注册
// 声明注入面防护 #71）与 RS256 的 Sign 完全同一套（#86）。header 硬契约同形态：
// 缺省只含 {"alg":"HS256"}，WithKeyID 显式追加 kid（#195），不带 typ。
func (s *SymmetricSigner) Sign(opts ...SignOption) (string, error) {
	if s == nil || len(s.secret) == 0 {
		// 哨兵错误（#139）：与 RS256 形态（jwt.go Sign 的错误面）对称——外层可
		// errors.Is(ErrInvalidToken)，调用方对签名路径的失败可统一分流。
		return "", fmt.Errorf("%w: 缺少 HS256 共享密钥", ErrInvalidToken)
	}
	payload, header, err := signParts("HS256", opts)
	if err != nil {
		return "", err
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims(payload))
	tok.Header = header
	return tok.SignedString(s.secret)
}

// ParseSymmetric 校验并解析 HS256 令牌——与 Parse（RS256）同构（#86）：同 Claims
// （注册声明收进 RegisteredClaims、其余进 Extra）、同 ParseOption（WithLeeway/
// WithAudience/#66、WithExpectedIssuer/#95、WithAllowNoExpiry/#135）、同错误链
// （外层哨兵 ErrInvalidToken 与 gojwt 底层 sentinel ErrTokenExpired/
// ErrTokenSignatureInvalid 等双可 errors.Is，#70）。安全缺省同 Parse：强制 exp
// （#135，WithAllowNoExpiry 豁免）与缺省 leeway 30s（#137，WithLeeway 覆盖）。
//
// alg 混淆防护（#86）：入口绑定算法——gojwt.WithValidMethods(["HS256"]) 单算法
// 白名单，RS256 令牌（无论密钥对真假）在本入口一律拒绝；RS256 的 Parse 同理只认
// RS256。密钥形态绑定算法，杜绝「用 HMAC 密钥校验非对称签名」的经典 CVE 形态。
func ParseSymmetric(token string, secret []byte, opts ...ParseOption) (*Claims, error) {
	o := &parseOptions{leeway: defaultLeeway}
	for _, opt := range opts {
		opt(o)
	}
	if o.rsaKeyByID != nil {
		return nil, fmt.Errorf("%w: WithKeyIDResolver 只适用于 RS256 入口 Parse（HS256 请用 WithSymmetricKeyIDResolver）", ErrInvalidToken)
	}
	if o.symKeyByID == nil {
		if err := checkSecret(secret); err != nil {
			// 双 %w 保留内层错误链（#139）：%v 会把链拍平成纯文本，调用方无法
			// errors.Is 穿透内层哨兵（同包 #70 双 %w 纪律的漏网点）。
			return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
		}
	}
	tok, err := newParser(o, "HS256").Parse(token, func(t *gojwt.Token) (any, error) {
		if o.symKeyByID != nil {
			// #195 多钥轮换：按 header kid 选共享密钥；选中密钥仍走同一强度
			// 判据（密钥环里的弱密钥不能成为绕过 NewSymmetric 的缺口）。
			kid, err := headerKeyID(t.Header)
			if err != nil {
				return nil, err
			}
			key, err := o.symKeyByID(kid)
			if err != nil {
				return nil, fmt.Errorf("按 kid %q 选共享密钥: %w", kid, err)
			}
			if err := checkSecret(key); err != nil {
				return nil, fmt.Errorf("按 kid %q 选中的共享密钥不可用: %w", kid, err)
			}
			return key, nil
		}
		return secret, nil
	})
	if err != nil {
		// 双 %w 保留底层错误链（同 Parse/#70）。
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	return claimsFromToken(tok)
}
