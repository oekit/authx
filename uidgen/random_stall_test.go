package uidgen

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// stallReader 是恒返回被拒字节的注入随机源（#190）：全 0xFF 填充，配
// len(runes)=3 的 alphabet（maxMultiple = 256-256%3 = 255，字节 255 恒被
// 丢弃）时拒绝采样一轮零产出——修复前 `for len(out) < n` 永不满足。
type stallReader struct{ b byte }

func (r stallReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

// stallRand 把 randRead 桩成恒 0xFF 的源（E 变体注入面），随测试还原。
func stallRand(t *testing.T) {
	t.Helper()
	old := randRead
	randRead = func(b []byte) (int, error) {
		for i := range b {
			b[i] = 0xFF
		}
		return len(b), nil
	}
	t.Cleanup(func() { randRead = old })
}

// stallTimeout 把「有限步内退出」变成断言：修复前死循环转成 2s 快速失败，
// 而不是让整个测试套件干等到包级超时（#190 的失败形态就是挂死，测试必须
// 比挂死先叫停）。
const stallTimeout = 2 * time.Second

// TestRandomStringFrom_StalledReaderErrors 钉住 #190：读满但恒产出被拒字节
// 的 broken reader 不得把公开 API 挂死——有限步内返回拒绝采样无进展错误。
func TestRandomStringFrom_StalledReaderErrors(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		_, err := RandomStringFrom(stallReader{b: 0xFF}, "abc", 8)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("恒 0xFF 的随机源必须报错，不得返回「成功」空结果")
		}
		if !errors.Is(err, errSampleStalled) {
			t.Fatalf("应为拒绝采样无进展错误, got %v", err)
		}
		if !strings.Contains(err.Error(), "无进展") {
			t.Errorf("文案应点明无进展, got %s", err)
		}
	case <-time.After(stallTimeout):
		t.Fatal("RandomStringFrom 被 broken reader 挂死（#190）")
	}
}

// TestRandomStringE_StalledRandErrors 钉住 E 变体同款出口：错误必须是
// 无进展哨兵本身，且不套「crypto/rand 不可用」的壳——随机源在读、只是不
// 产出可采样字节，套读取失败的壳会把根因引偏。
func TestRandomStringE_StalledRandErrors(t *testing.T) {
	stallRand(t)
	done := make(chan error, 1)
	go func() {
		_, err := RandomStringE("abc", 8)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("恒 0xFF 的 randRead 必须返回 error")
		}
		if !errors.Is(err, errSampleStalled) {
			t.Fatalf("应为拒绝采样无进展错误, got %v", err)
		}
		if strings.Contains(err.Error(), "crypto/rand 不可用") {
			t.Errorf("无进展不得套读取失败的壳（根因引偏）, got %s", err)
		}
	case <-time.After(stallTimeout):
		t.Fatal("RandomStringE 被无进展随机源挂死（#190）")
	}
}

// TestRandomString_StalledRandPanics 钉住 panic 版随之 panic（#190：与随机源
// 读取失败同口径，非法/不可用状态当场暴露，不静默返回、更不挂死）。
func TestRandomString_StalledRandPanics(t *testing.T) {
	stallRand(t)
	done := make(chan any, 1)
	go func() {
		var r any
		func() {
			defer func() { r = recover() }()
			_ = RandomString("abc", 8)
		}()
		done <- r
	}()
	select {
	case r := <-done:
		if r == nil {
			t.Fatal("采样无进展在 panic 版必须 panic")
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, "无进展") {
			t.Errorf("panic 文案应点明无进展, got %s", msg)
		}
	case <-time.After(stallTimeout):
		t.Fatal("RandomString 被无进展随机源挂死（#190）")
	}
}

// TestSampleRunes_RealSourceUnaffected 钉住判据不误伤：真实随机源（本机
// crypto/rand）在各 alphabet 尺寸下照常采样——进度判据只在「连续 64 轮
// 零产出」时触发，正常路径每轮都有产出、stall 归零。
func TestSampleRunes_RealSourceUnaffected(t *testing.T) {
	for _, alphabet := range []string{"ab", "abc", "abcdefg", "0123456789abcdefghijklmnopqrstuvwxyz"} {
		s, err := RandomStringE(alphabet, 64)
		if err != nil {
			t.Fatalf("RandomStringE(%q) error = %v", alphabet, err)
		}
		if len([]rune(s)) != 64 {
			t.Fatalf("RandomStringE(%q) 长度 = %d, want 64", alphabet, len([]rune(s)))
		}
		for _, r := range s {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("字符 %q 不在 alphabet %q 内", r, alphabet)
			}
		}
	}
}
