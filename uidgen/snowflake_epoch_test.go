package uidgen

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestSnowflake_Next_ClockBeforeEpoch_Panics 钉住 #189：系统时钟早于
// snowflakeEpoch（2025-01-01，冷启动未同步 NTP/RTC 掉电/人为调时）时
// next() 必须拒绝发号，不得静默返回负 ID——负 ID 违反位布局 sign 恒 0 的
// 承诺：ExtractSnowflakeTime 解出 1970 年代的错误时间、下游转 uint64 变
// 补码大数、按正数主键假设的 base32/base58 编码静默出错。
// 构造：把 epoch 抬到未来（等价于真实时钟早于 epoch），无需注入假时钟。
func TestSnowflake_Next_ClockBeforeEpoch_Panics(t *testing.T) {
	s := &Snowflake{
		epoch:              time.Now().UnixMilli() + int64(time.Hour/time.Millisecond), // now < epoch
		machineID:          1,
		clockBackTolerance: defaultClockBackTolerance,
	}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("时钟早于 epoch 必须 fail-fast 拒绝发号（#189）")
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, "snowflakeEpoch") {
			t.Errorf("panic 文案应点名 snowflakeEpoch, got %s", msg)
		}
	}()
	_ = s.next()
}

// TestSnowflake_Next_OverflowPanics 钉住 #189 的另一端：now-epoch 超出 41 位
// 毫秒窗口（约 69.7 年，即 2094 年前后）时左移吃掉 bit63、ID 变负——
// makeID 的结果侧兜底当场 panic，不让负 ID 流出（脏 ID 进库后不可收回）。
func TestSnowflake_Next_OverflowPanics(t *testing.T) {
	s := &Snowflake{
		epoch:              time.Now().UnixMilli() - (1 << 41) - 60_000, // now-epoch > 2^41
		machineID:          1,
		clockBackTolerance: defaultClockBackTolerance,
	}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("溢出为负的 ID 必须当场 panic（#189）")
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, "溢出为负") {
			t.Errorf("panic 文案应点明溢出, got %s", msg)
		}
	}()
	_ = s.next()
}

// TestSnowflake_Next_ValidClockStillPositive 钉住守卫不误伤：正常时钟下
// （now ≥ epoch 且未溢出）发号照常，ID 恒为正（位布局 sign=0 的承诺）。
func TestSnowflake_Next_ValidClockStillPositive(t *testing.T) {
	s := &Snowflake{
		epoch:              snowflakeEpoch,
		machineID:          7,
		clockBackTolerance: defaultClockBackTolerance,
	}
	for i := 0; i < 100; i++ {
		id := s.next()
		if id <= 0 {
			t.Fatalf("正常时钟下 ID 必须为正, got %d", id)
		}
	}
}
