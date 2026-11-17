package uidgen

import (
	"strings"

	"github.com/oekit/pkg/stringx"
)

// newV4 生成 RFC 4122 v4 UUID 的规范形式（小写、连字符分隔）。
// 委托 pkg/stringx.UUIDv4() 全矩阵单源（#531，#528 消费方迁移）：16 字节
// crypto/rand、第 7 字节高 4 位置版本号 4、第 9 字节高 2 位置 variant 10、
// 8-4-4-4-12 连字符格式，输出与原手写实现逐字节一致（对拍 1000 例通过）。
// 随机源失败 panic 语义不变（pkg 侧同为 panic；panic 消息文案归 pkg）。
func newV4() string {
	return stringx.UUIDv4()
}

// UUID 返回一个不带连字符的 UUID 字符串。
func UUID() string {
	return strings.ReplaceAll(newV4(), "-", "")
}

// ShortUUID 返回一个 16 位的短 UUID。
func ShortUUID() string {
	return UUID()[:16]
}

// UUIDToUpper 返回大写的 UUID 字符串。
func UUIDToUpper() string {
	return strings.ToUpper(UUID())
}

// ShortUUIDToUpper 返回大写的 16 位短 UUID。
func ShortUUIDToUpper() string {
	return UUIDToUpper()[:16]
}

// UUIDWithHyphen 返回带连字符的 UUID 字符串。
func UUIDWithHyphen() string {
	return newV4()
}
