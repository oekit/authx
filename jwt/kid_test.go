package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	bizerrors "github.com/oekit/pkg/errors"
)

// testFixedSignTime 固定签发时刻（确定性令牌字节；取未来时刻保证 exp 有效）。
func testFixedSignTime() time.Time {
	return time.Unix(4102444800, 0).UTC()
}

// decodeHeaderJSON 解 JWT header 段的原始 JSON 文本（字节级断言用）。
func decodeHeaderJSON(t *testing.T, token string) string {
	t.Helper()
	parts := splitToken(token)
	if len(parts) != 3 {
		t.Fatalf("token parts = %d, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	return string(raw)
}

// #195 验收：WithKeyID 写入 header 的 kid，header 恰为 {"alg":"RS256","kid":"k1"}，
// 验签与 claims 校验不受影响。
func TestSignWithKeyIDHeaderRS256(t *testing.T) {
	kp := newTestKeyPair(t)
	fixed := testFixedSignTime()
	token, err := Sign(kp,
		WithIssuer("iss"),
		WithKeyID("k1"),
		WithSubject("u1"),
		WithTTL(time.Hour),
		WithIssuedAt(fixed),
	)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if got, want := decodeHeaderJSON(t, token), `{"alg":"RS256","kid":"k1"}`; got != want {
		t.Fatalf("header JSON = %s, want %s", got, want)
	}
	hdr := decodeSegment(t, token, 0)
	if len(hdr) != 2 || hdr["alg"] != "RS256" || hdr["kid"] != "k1" {
		t.Fatalf("header = %v, want 恰含 alg/kid", hdr)
	}

	claims, err := Parse(token, kp.Public)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if claims.Issuer != "iss" || claims.Subject != "u1" {
		t.Fatalf("claims = {iss:%q sub:%q}", claims.Issuer, claims.Subject)
	}
	if got := claims.KeyID(); got != "k1" {
		t.Fatalf("Claims.KeyID() = %q, want k1", got)
	}
	if claims.Header["alg"] != "RS256" || claims.Header["kid"] != "k1" {
		t.Fatalf("Claims.Header = %v, want alg/kid 快照", claims.Header)
	}
}

// #195 回归：不设置 WithKeyID 时 header 字节零变化（仍恰为 {"alg":"RS256"}，
// 无 typ / 无 kid），同一 payload 与手工按旧契约构造的令牌逐字节一致。
func TestSignWithoutKeyIDBytesUnchanged(t *testing.T) {
	kp := newTestKeyPair(t)
	fixed := testFixedSignTime()
	token, err := Sign(kp,
		WithIssuer("iss"),
		WithSubject("u1"),
		WithTTL(time.Hour),
		WithIssuedAt(fixed),
	)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if got, want := decodeHeaderJSON(t, token), `{"alg":"RS256"}`; got != want {
		t.Fatalf("无 kid header JSON = %s, want %s（字节零变化）", got, want)
	}

	// 旧契约手工令牌：同一 header/payload/算法，RSA PKCS#1 v1.5 签名确定。
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims{
		"iss": "iss",
		"sub": "u1",
		"iat": fixed.Unix(),
		"exp": fixed.Add(time.Hour).Unix(),
	})
	tok.Header = map[string]any{"alg": "RS256"}
	legacy, err := tok.SignedString(kp.Private)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	if token != legacy {
		t.Fatalf("无 kid 签发字节发生变化：\n got %s\nwant %s", token, legacy)
	}
}

// WithKeyID("") 是显式回退默认值（nil 参数同理）：不写 kid，不 panic。
func TestWithKeyIDEmptyFallsBackToAlgOnly(t *testing.T) {
	kp := newTestKeyPair(t)
	token, err := Sign(kp, WithSubject("u"), WithTTL(time.Hour), WithKeyID(""))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if got, want := decodeHeaderJSON(t, token), `{"alg":"RS256"}`; got != want {
		t.Fatalf("WithKeyID(\"\") header = %s, want %s", got, want)
	}
}

// #195 解析侧：多钥轮换直接用 header kid 选钥，无需调用方自拆 token。
func TestParseWithKeyIDResolver(t *testing.T) {
	k1 := newTestKeyPair(t)
	k2 := newTestKeyPair(t)
	keys := map[string]*rsa.PublicKey{"k1": k1.Public, "k2": k2.Public}
	resolve := func(kid string) (*rsa.PublicKey, error) {
		pub, ok := keys[kid]
		if !ok {
			return nil, bizerrors.Newf("未知 kid %q", kid)
		}
		return pub, nil
	}

	token, err := Sign(k2, WithSubject("u1"), WithKeyID("k2"), WithTTL(time.Hour))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	claims, err := Parse(token, nil, WithKeyIDResolver(resolve))
	if err != nil {
		t.Fatalf("Parse(WithKeyIDResolver) error = %v", err)
	}
	if claims.Subject != "u1" || claims.KeyID() != "k2" {
		t.Fatalf("claims = {sub:%q kid:%q}", claims.Subject, claims.KeyID())
	}

	// 未知 kid ⇒ fail-closed，错误链保留解析器原因与外层哨兵。
	_, err = Parse(token, nil, WithKeyIDResolver(func(string) (*rsa.PublicKey, error) {
		return nil, bizerrors.New("密钥环查询失败")
	}))
	if !errors.Is(err, ErrInvalidToken) || !strings.Contains(err.Error(), "密钥环查询失败") {
		t.Fatalf("未知 kid 必须拒绝并保留原因，got %v", err)
	}
	// 解析器返回 nil 公钥 ⇒ 拒绝，不得 panic。
	if _, err := Parse(token, nil, WithKeyIDResolver(func(string) (*rsa.PublicKey, error) {
		return nil, nil
	})); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("nil 公钥必须拒绝，got %v", err)
	}
	// 解析器选中错误密钥 ⇒ 验签失败（错误链可判签名哨兵）。
	if _, err := Parse(token, nil, WithKeyIDResolver(func(string) (*rsa.PublicKey, error) {
		return k1.Public, nil
	})); !errors.Is(err, ErrInvalidToken) || !errors.Is(err, gojwt.ErrTokenSignatureInvalid) {
		t.Fatalf("错密钥必须验签失败，got %v", err)
	}

	// 无 kid 令牌 + resolver ⇒ 无法选钥，fail-closed。
	noKid, err := Sign(k1, WithSubject("u1"), WithTTL(time.Hour))
	if err != nil {
		t.Fatalf("Sign(no kid) error = %v", err)
	}
	if _, err := Parse(noKid, nil, WithKeyIDResolver(resolve)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("无 kid + resolver 必须拒绝，got %v", err)
	}

	// 兼容：未配置 resolver 时 pub 仍必填（既有错误面不变）。
	if _, err := Parse(token, nil); err == nil || !strings.Contains(err.Error(), "缺少公钥") {
		t.Fatalf("无 resolver + nil pub 必须报缺少公钥，got %v", err)
	}
	// resolver 与 pub 并存时 resolver 优先（pub 可为零值）。
	if _, err := Parse(token, &rsa.PublicKey{}, WithKeyIDResolver(resolve)); err != nil {
		t.Fatalf("resolver 优先于 pub 参数，error = %v", err)
	}
	// 入口与 resolver 形态错配 ⇒ fail-fast（不静默忽略配置）。
	if _, err := Parse(token, k1.Public, WithSymmetricKeyIDResolver(func(string) ([]byte, error) {
		return testHS256Secret(t), nil
	})); !errors.Is(err, ErrInvalidToken) || !strings.Contains(err.Error(), "WithSymmetricKeyIDResolver") {
		t.Fatalf("RS256 入口传 HS256 resolver 必须报错，got %v", err)
	}
}

// #195 HS256：同一 SignOption 面支持 kid；解析侧按 kid 选共享密钥。
func TestSymmetricKeyID(t *testing.T) {
	secret1 := []byte("0123456789abcdef0123456789abcdef")
	secret2 := []byte("fedcba9876543210fedcba9876543210")
	signer, err := NewSymmetric(secret2)
	if err != nil {
		t.Fatalf("NewSymmetric() error = %v", err)
	}
	token, err := signer.Sign(WithSubject("u1"), WithKeyID("h2"), WithTTL(time.Hour))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if got, want := decodeHeaderJSON(t, token), `{"alg":"HS256","kid":"h2"}`; got != want {
		t.Fatalf("HS256 header JSON = %s, want %s", got, want)
	}
	resolve := func(kid string) ([]byte, error) {
		switch kid {
		case "h1":
			return secret1, nil
		case "h2":
			return secret2, nil
		default:
			return nil, bizerrors.Newf("未知 kid %q", kid)
		}
	}
	claims, err := ParseSymmetric(token, nil, WithSymmetricKeyIDResolver(resolve))
	if err != nil {
		t.Fatalf("ParseSymmetric(WithSymmetricKeyIDResolver) error = %v", err)
	}
	if claims.Subject != "u1" || claims.KeyID() != "h2" {
		t.Fatalf("claims = {sub:%q kid:%q}", claims.Subject, claims.KeyID())
	}
	// 未知 kid ⇒ 拒绝。
	if _, err := ParseSymmetric(token, nil, WithSymmetricKeyIDResolver(func(string) ([]byte, error) {
		return nil, bizerrors.New("密钥环故障")
	})); !errors.Is(err, ErrInvalidToken) || !strings.Contains(err.Error(), "密钥环故障") {
		t.Fatalf("未知 kid 必须拒绝并保留原因，got %v", err)
	}
	// 无 kid 令牌 + resolver ⇒ fail-closed。
	noKid, err := signer.Sign(WithSubject("u1"), WithTTL(time.Hour))
	if err != nil {
		t.Fatalf("Sign(no kid) error = %v", err)
	}
	if _, err := ParseSymmetric(noKid, nil, WithSymmetricKeyIDResolver(resolve)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("无 kid + resolver 必须拒绝，got %v", err)
	}
	// 无 kid 签发字节不变。
	if got, want := decodeHeaderJSON(t, noKid), `{"alg":"HS256"}`; got != want {
		t.Fatalf("HS256 无 kid header = %s, want %s", got, want)
	}
	// 入口与 resolver 形态错配 ⇒ fail-fast。
	if _, err := ParseSymmetric(token, secret2, WithKeyIDResolver(func(string) (*rsa.PublicKey, error) {
		return nil, nil
	})); !errors.Is(err, ErrInvalidToken) || !strings.Contains(err.Error(), "WithKeyIDResolver") {
		t.Fatalf("HS256 入口传 RS256 resolver 必须报错，got %v", err)
	}
}

// Manager 轮换继承 kid：同一签名密钥轮换出的新令牌不丢 header kid（#195）。
func TestManagerRefreshInheritsKeyID(t *testing.T) {
	m, err := NewManagerHS256(testHS256Secret(t))
	if err != nil {
		t.Fatalf("NewManagerHS256() error = %v", err)
	}
	_, refresh, err := m.IssuePair("u1", time.Minute, time.Hour, WithKeyID("h1"))
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	_, rotated, err := m.Refresh(refresh, time.Minute, time.Hour, nil)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	claims, err := m.ParseTyped(TokenRefresh, rotated)
	if err != nil {
		t.Fatalf("ParseTyped(rotated) error = %v", err)
	}
	if got := claims.KeyID(); got != "h1" {
		t.Fatalf("轮换后 KeyID = %q, want h1（kid 随密钥身份继承）", got)
	}
}

// Manager 签发面透传 WithKeyID：成对令牌都带 kid，ParseTyped 可读回。
func TestManagerIssuePairWithKeyID(t *testing.T) {
	kp := newTestKeyPair(t)
	m, err := NewManagerRS256(kp)
	if err != nil {
		t.Fatalf("NewManagerRS256() error = %v", err)
	}
	access, refresh, err := m.IssuePair("u1", time.Minute, time.Hour, WithKeyID("k1"))
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}
	for name, token := range map[string]string{"access": access, "refresh": refresh} {
		if got, want := decodeHeaderJSON(t, token), `{"alg":"RS256","kid":"k1"}`; got != want {
			t.Fatalf("[%s] header = %s, want %s", name, got, want)
		}
	}
	claims, err := m.ParseTyped(TokenAccess, access)
	if err != nil {
		t.Fatalf("ParseTyped(access) error = %v", err)
	}
	if claims.KeyID() != "k1" {
		t.Fatalf("ParseTyped access KeyID = %q, want k1", claims.KeyID())
	}
}
