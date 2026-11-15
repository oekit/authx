// crypto/rand 随机串生成（标识符/密钥面）：与 Snowflake（可预测、仅作 ID）分居——
// 密钥、一次性凭据、高熵标识符必须走本文件。
package uidgen

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// randRead 是 crypto/rand.Read 的间接层，仅供测试注入必然失败的桩（#87：运行期
// 环境故障的 error 出口要能测）。
var randRead = rand.Read

// errSampleStalled 是拒绝采样无进展的哨兵（#190，errors.Is 可辨）：随机源
// 连续多轮读满采样缓冲却零产出——注入源恒返回被拒字节（如只吐 0xFF）、
// 坏随机源吐固定 padding 时，`for len(out) < n` 永不满足，公开 API 会被
// 单个入参挂死（error 出口在「死循环」这种失败形态上完全无用）。
var errSampleStalled = errors.New("uidgen: 拒绝采样无进展（随机源未产出合法字节）")

// maxStallRounds 是拒绝采样的无进展判定阈值（#190）：连续这么多轮读满
// 采样缓冲（每轮 n+8 字节）却零产出即报错退出。取 64 的依据：接受率
// maxMultiple/256 的最小值约 129/256（len(runes)=129），真实随机源连续
// 64 轮零产出是天文小概率，只有恒吐被拒字节的注入源/坏源才会撞上——
// 判据对正常路径零影响，对挂死路径是确定的有限步退出。
const maxStallRounds = 64

// RandomHex n 字节 crypto/rand 随机数的十六进制串（2n 字符）。
// nBytes <= 0 直接 panic（#50）：对标识符场景「非法长度=调用方 bug」，对密钥/
// 凭据场景静默空串是**最危险的缺省**——「名义生成了、实际是空钥匙」（空串做
// HMAC key / API token 落库后患无穷），与 RandomString 空 alphabet 的防呆哲学
// 对齐：非法入参启动即暴露好过静默降级。长度来自配置面时请在构造期校验。
// crypto/rand 读取失败（运行期环境故障）同样 panic——请求路径请用 RandomHexE（#87）。
//
// 适用：对象 ID、webhook secret、审批 HMAC 密钥等高熵标识符与密钥面。
func RandomHex(nBytes int) string {
	checkHexArgs(nBytes)
	b, err := randomBytes(nBytes)
	if err != nil {
		panic(err.Error())
	}
	return hex.EncodeToString(b)
}

// RandomHexE 是 RandomHex 的 error 返回变体（#87）：入参校验与 RandomHex 完全
// 一致（nBytes <= 0 仍 panic——非法入参是调用方 bug，防呆哲学不变）；差异仅在
// crypto/rand 读取失败这一**运行期环境故障**——panic 版会把它升级成进程崩溃，
// 本版返回 error，请求路径（nonce/token/上传会话 ID）可就地降级处理，不必再因
// 「没有 error 出口」而吞错或自己手搓 make+rand.Read+hex。
func RandomHexE(nBytes int) (string, error) {
	checkHexArgs(nBytes)
	b, err := randomBytes(nBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RandomHexFrom 是 RandomHex 的显式随机源变体（#87）：从 r 读满 nBytes 字节后
// hex 编码，专供测试注入确定性/必然失败的随机源（也供调用方自带可信随机源）。
// 入参校验与 RandomHex 同款（nBytes <= 0 panic，checkHexArgs 单一来源）；nil
// reader 视为非法入参 panic——显式源是调用方的承诺，nil 不是「用默认」。
// 读取语义 io.ReadFull：注入短读 reader（如每次只吐 3 字节）循环读满。
func RandomHexFrom(r io.Reader, nBytes int) (string, error) {
	checkHexArgs(nBytes)
	if r == nil {
		panic("uidgen: RandomHexFrom 随机源 reader 为 nil")
	}
	b := make([]byte, nBytes)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("uidgen: 随机源读取失败: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// checkHexArgs 校验 RandomHex/RandomHexE 的入参（两形态同款防呆，非法入参当场暴露）。
func checkHexArgs(nBytes int) {
	if nBytes <= 0 {
		panic("uidgen: RandomHex 字节数必须为正（got " + strconv.Itoa(nBytes) + "）——空串密钥是最危险的缺省，密钥/凭据场景漏个非正长度必须当场暴露")
	}
}

// randomBytes 读 n 字节 crypto/rand（#87：panic 版与 E 版共用同一读取线，错误
// 文案单一来源）。
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := randRead(b); err != nil {
		return nil, fmt.Errorf("uidgen: crypto/rand 不可用: %w", err)
	}
	return b, nil
}

// RandomString 从 alphabet 均匀采样 n 个字符（rune 语义：多字节 alphabet 产出
// 合法 UTF-8，输出恰含 n 个字符；#89）——拒绝采样消模偏差，无 mod 偏置。
//
// 入参防呆（全部当场 panic）：
//   - n <= 0 直接 panic（#88）：与 #50 对 RandomHex 的修法同口径——空串密钥是
//     最危险的缺省（「名义生成了、实际是空钥匙」），长度来自配置面时请在构造
//     期校验；
//   - alphabet 为空 panic；
//   - alphabet 字符数 > 256 panic（#52：拒绝采样 maxMultiple 归 0 ⇒ 死循环；
//     #89 起判据按 rune 数计，字节口径下的多字节大字符集不再被误伤）。
//
// crypto/rand 读取失败（运行期环境故障）同样 panic——请求路径请用 RandomStringE（#87）。
// 随机源恒产出被拒字节导致的拒绝采样无进展同样 panic（#190，有限步内暴露，
// 不挂死）。适用：带自定义字符集的短 ID/令牌。
func RandomString(alphabet string, n int) string {
	s, err := RandomStringE(alphabet, n)
	if err != nil {
		panic(err.Error())
	}
	return s
}

// RandomStringE 是 RandomString 的 error 返回变体（#87）：入参校验与 RandomString
// 完全一致（n <= 0 / 空 alphabet / 字符数 >256 仍 panic——非法入参是调用方 bug）；
// 差异仅在 crypto/rand 读取失败这一运行期环境故障返回 error 而非 panic。取样经
// 共享核心 sampleRunes（显式随机源变体 RandomStringFrom 同款），拒绝采样实现
// 只此一份（无第二份 256%len 偏差修复代码）。
// 另一 error 出口（#190）：随机源读满但连续 maxStallRounds 轮零产出（拒绝采样
// 无进展）时原样返回该错误——「死循环」这种失败形态不再挂死调用方。
func RandomStringE(alphabet string, n int) (string, error) {
	runes := checkStringArgs(alphabet, n)
	s, err := sampleRunes(randRead, runes, n)
	if err != nil {
		// 无进展（#190）不是「读取失败」：随机源在读、只是不产出可采样
		// 字节，套 crypto/rand 不可用 的壳会把根因引偏，原样上抛。
		if errors.Is(err, errSampleStalled) {
			return "", err
		}
		return "", fmt.Errorf("uidgen: crypto/rand 不可用: %w", err)
	}
	return s, nil
}

// sampleRunes 是 RandomString 族（panic/E/From 三形态）的共享取样核心（#87）：
// 拒绝采样（256%len 偏差修复）只此一份——read 抽象让 E 版（randRead 桩注入）与
// From 版（io.Reader 注入）共用同一份循环与单字符快路径。read 必须填满 b 或返回
// 错误（crypto/rand.Read 天然如此；From 版经 io.ReadFull 达成同一语义）。
//
// 失败形态（#190）：read 满足读满语义但**取不到合法字节**（注入源恒返回被拒
// 字节）时，循环原本没有退出条件——连续 maxStallRounds 轮零产出即返回
// errSampleStalled（包住它，errors.Is 可辨），RandomString/RandomStringE/
// RandomStringFrom 不再被单个入参挂死；随机源自身的读取错误仍原样上抛。
func sampleRunes(read func([]byte) (int, error), runes []rune, n int) (string, error) {
	if len(runes) == 1 {
		out := make([]rune, n)
		for i := range out {
			out[i] = runes[0]
		}
		return string(out), nil
	}
	// 拒绝采样：256 % len 会造成高位取值偏差，丢弃 >= maxMultiple 的字节。
	maxMultiple := 256 - 256%len(runes)
	out := make([]rune, 0, n)
	buf := make([]byte, n+8)
	stall := 0
	for len(out) < n {
		if _, err := read(buf); err != nil {
			return "", err
		}
		before := len(out)
		for _, c := range buf {
			if int(c) < maxMultiple {
				out = append(out, runes[int(c)%len(runes)])
				if len(out) == n {
					break
				}
			}
		}
		if len(out) == before {
			stall++
			if stall >= maxStallRounds {
				return "", fmt.Errorf("连续 %d 轮读满 %d 字节零产出: %w", stall, len(buf), errSampleStalled)
			}
		} else {
			stall = 0
		}
	}
	return string(out), nil
}

// RandomStringFrom 是 RandomString 的显式随机源变体（#87）：从 r 取样，与
// RandomString/RandomStringE 共用同一份拒绝采样实现（sampleRunes，无第二份
// 256%len 偏差修复代码）。入参校验同 panic 版（n<=0 / 空 alphabet / 字符数
// >256 panic，checkStringArgs 单一来源）；nil reader 视为非法入参 panic。
// 读取语义 io.ReadFull：注入短读 reader（如每次只吐 3 字节）循环读满。
//
// 失败形态（#190）：读满但恒产出被拒字节的 reader（全 0xFF 填充、写错的
// 测试桩）此前会让拒绝采样循环永不满足 len(out)==n、把调用方 goroutine
// 挂死——现在连续 maxStallRounds 轮零产出返回拒绝采样无进展错误
// （errors.Is(errSampleStalled) 可辨），有限步内退出。
func RandomStringFrom(r io.Reader, alphabet string, n int) (string, error) {
	runes := checkStringArgs(alphabet, n)
	if r == nil {
		panic("uidgen: RandomStringFrom 随机源 reader 为 nil")
	}
	s, err := sampleRunes(func(b []byte) (int, error) { return io.ReadFull(r, b) }, runes, n)
	if err != nil {
		// 无进展（#190）不是「读取失败」：reader 在读、只是不产出可采样
		// 字节，套随机源读取失败 的壳会把根因引偏，原样上抛。
		if errors.Is(err, errSampleStalled) {
			return "", err
		}
		return "", fmt.Errorf("uidgen: 随机源读取失败: %w", err)
	}
	return s, nil
}

// checkStringArgs 校验 RandomString/RandomStringE 的入参并返回 rune 形态的
// alphabet（#89 起全程按字符处理）：非法入参 panic 当场暴露，不静默降级。
func checkStringArgs(alphabet string, n int) []rune {
	if n <= 0 {
		panic(fmt.Sprintf("uidgen: RandomString 采样长度必须为正（got %d）——空串密钥是最危险的缺省，密钥/凭据场景漏个非正长度必须当场暴露（#88，对齐 #50）", n))
	}
	if len(alphabet) == 0 {
		panic("uidgen: 空 alphabet")
	}
	runes := []rune(alphabet)
	if len(runes) > 256 {
		panic(fmt.Sprintf("uidgen: alphabet 字符数 %d > 256，拒绝采样 maxMultiple 归 0 ⇒ RandomString 死循环（#52）——非法入参当场暴露（对齐 #50 哲学）", len(runes)))
	}
	return runes
}
