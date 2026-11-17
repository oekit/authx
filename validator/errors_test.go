package validator

import (
	stderrors "errors"
	"fmt"
	"testing"

	bizerrors "github.com/oekit/pkg/errors"
)

// TestValidationError_Error_Empty covers the no-errors path:
// returns the default "validation failed" message.
func TestValidationError_Error_Empty(t *testing.T) {
	ve := &ValidationError{}
	if got := ve.Error(); got != "validation failed" {
		t.Errorf("expected 'validation failed', got %q", got)
	}
}

// TestValidationError_Error_Single covers the single-error path:
// returns that error's message.
func TestValidationError_Error_Single(t *testing.T) {
	ve := &ValidationError{errors: []FieldError{{Field: "name", Message: "name required"}}}
	if got := ve.Error(); got != "name required" {
		t.Errorf("expected 'name required', got %q", got)
	}
}

// TestValidationError_Unwrap verifies the Unwrap method returns a
// *BizError with code 400. This is what makes handler.ErrorRespBiz
// map the validation error to HTTP 400.
func TestValidationError_Unwrap(t *testing.T) {
	ve := &ValidationError{errors: []FieldError{{Field: "name", Message: "name required"}}}
	unwrapped := ve.Unwrap()

	var be *bizerrors.BizError
	if !stderrors.As(unwrapped, &be) {
		t.Fatalf("expected *BizError from Unwrap, got %T", unwrapped)
	}
	if be.BizCode != 400 {
		t.Errorf("expected BizCode=400, got %d", be.BizCode)
	}
	if be.HTTPCode != 400 {
		t.Errorf("expected HTTPCode=400, got %d", be.HTTPCode)
	}
}

// TestValidationError_Unwrap_Nested verifies errors.As walks
// through the ValidationError → BizError chain.
func TestValidationError_Unwrap_Nested(t *testing.T) {
	ve := &ValidationError{errors: []FieldError{{Field: "x", Message: "bad"}}}
	var be *bizerrors.BizError
	if !stderrors.As(ve, &be) {
		t.Fatal("expected errors.As to find *BizError through Unwrap chain")
	}
	if be.BizCode != 400 {
		t.Errorf("expected BizCode=400, got %d", be.BizCode)
	}
}

// #208：Unwrap 载体缓存——同一错误值反复 Unwrap 返回同一实例（此前每次
// 现场 new，身份永不稳定），且 errors.Is 对包级载体 ErrValidation 可判定
// （经 Is 桥接）；errors.As 仍取到携带真实字段消息的载体（mw.Fail 响应体
// message 保真口径）。
func TestValidationError_Unwrap_CachedCarrier(t *testing.T) {
	ve := NewFieldValidationError([]FieldError{{Field: "name", Message: "name is required"}})
	first := ve.Unwrap()
	if first != ve.Unwrap() {
		t.Fatal("同一错误值反复 Unwrap 必须返回同一实例（sync.Once 缓存载体）")
	}
	if !stderrors.Is(ve, ErrValidation) {
		t.Fatal("errors.Is(err, ErrValidation) 必须命中包级缓存载体（#208 此前对任何 BizError 实例永不匹配）")
	}
	// 包装链上同样可判定（%w 包装与 Join 两条链式路径）。
	if !stderrors.Is(fmt.Errorf("wrapped: %w", ve), ErrValidation) {
		t.Fatal("包装后的 ValidationError 经 Unwrap 链仍须命中包级载体")
	}
	if !stderrors.Is(stderrors.Join(stderrors.New("ctx"), ve), ErrValidation) {
		t.Fatal("Join 链上的 ValidationError 亦须命中包级载体")
	}
	if stderrors.Is(ve, ErrNilValidationFunc) {
		t.Fatal("无关哨兵不得误判")
	}
	var be *bizerrors.BizError
	if !stderrors.As(ve, &be) {
		t.Fatal("errors.As 仍须命中 BizError 载体")
	}
	if be.BizCode != 400 || be.HTTPCode != 400 {
		t.Fatalf("codes = (%d, %d), want (400, 400)", be.BizCode, be.HTTPCode)
	}
	if be.Message != "name is required" {
		t.Fatalf("载体 message = %q, want 首条字段消息保真（mw.Fail 响应体口径）", be.Message)
	}
	// 直接构造（不经 NewFieldValidationError）同口径：零值 sync.Once 可用。
	literal := &ValidationError{errors: []FieldError{{Field: "x", Message: "x bad"}}}
	if literal.Unwrap() != literal.Unwrap() {
		t.Fatal("直接构造的错误值 Unwrap 亦须缓存")
	}
	if !stderrors.Is(literal, ErrValidation) {
		t.Fatal("直接构造的错误值 errors.Is 亦须命中包级载体")
	}
	// 空错误列表：载体 message 退到 "validation failed" 兜底文案（与 Error() 一致）。
	empty := &ValidationError{}
	if emptyBe, ok := empty.Unwrap().(*bizerrors.BizError); !ok || emptyBe.Message != "validation failed" {
		t.Fatalf("empty 载体 message = %v, want \"validation failed\"", empty.Unwrap())
	}
}

// TestAsValidationError_Nil covers the nil-error path.
func TestAsValidationError_Nil(t *testing.T) {
	if got, ok := AsValidationError(nil); ok || got != nil {
		t.Errorf("expected (nil, false), got (%v, %v)", got, ok)
	}
}

// TestAsValidationError_WrongType covers the wrong-type path.
func TestAsValidationError_WrongType(t *testing.T) {
	if got, ok := AsValidationError(stderrors.New("plain")); ok || got != nil {
		t.Errorf("expected (nil, false) for non-ValidationError, got (%v, %v)", got, ok)
	}
}

// TestIsValidationError covers the convenience wrapper.
func TestIsValidationError_Extended(t *testing.T) {
	ve := &ValidationError{errors: []FieldError{{Field: "x"}}}
	if !IsValidationError(ve) {
		t.Error("expected IsValidationError=true for *ValidationError")
	}
	if IsValidationError(stderrors.New("plain")) {
		t.Error("expected IsValidationError=false for plain error")
	}
	if IsValidationError(nil) {
		t.Error("expected IsValidationError=false for nil")
	}
}

// TestValidationError_Map_Direct covers the field→message map
// via direct struct construction (vs the existing TestValidationError_Map
// in validator_test.go which uses Validate()).
func TestValidationError_Map_Direct(t *testing.T) {
	ve := &ValidationError{errors: []FieldError{
		{Field: "name", Message: "required"},
		{Field: "age", Message: "must be > 0"},
	}}
	m := ve.Map()
	if m["name"] != "required" {
		t.Errorf("expected name=required, got %q", m["name"])
	}
	if m["age"] != "must be > 0" {
		t.Errorf("expected age=must be > 0, got %q", m["age"])
	}
	if len(m) != 2 {
		t.Errorf("expected 2 entries, got %d", len(m))
	}
}

// TestValidationError_Len covers the Len accessor.
func TestValidationError_Len(t *testing.T) {
	ve := &ValidationError{errors: []FieldError{{}, {}, {}}}
	if got := ve.Len(); got != 3 {
		t.Errorf("expected 3, got %d", got)
	}
	empty := &ValidationError{}
	if got := empty.Len(); got != 0 {
		t.Errorf("expected 0 for empty, got %d", got)
	}
}

// TestValidationError_String_Direct verifies the String() format
// includes all fields with their tags (vs the existing
// TestValidationError_String in validator_test.go which uses
// Validate() and only asserts non-empty).
func TestValidationError_String_Direct(t *testing.T) {
	ve := &ValidationError{errors: []FieldError{
		{Field: "name", Tag: "required"},
		{Field: "age", Tag: "gt"},
	}}
	got := ve.String()
	if want := "validation failed: name (required); age (gt)"; got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// TestNewFieldValidationError verifies the constructor stores the
// errors slice.
func TestNewFieldValidationError(t *testing.T) {
	fieldErrs := []FieldError{{Field: "x", Message: "y"}}
	ve := NewFieldValidationError(fieldErrs)
	if ve == nil {
		t.Fatal("expected non-nil ValidationError")
	}
	if ve.Len() != 1 {
		t.Errorf("expected 1 error, got %d", ve.Len())
	}
}

// #116：构造期拷贝入参——handler/validatorh 构造后复用底层数组做日志增强/
// 翻译是常见形态，调用方事后改写不得让已发布的错误值内容漂移（错误值按惯例
// 不可变，core#80 同构：已发布的快照不可被发布方事后改写）。
// 修复前断言失败：Error()/Map() 跟着入参改写变成 MUTATED-BY-CALLER。
func TestNewFieldValidationError_CopiesInput(t *testing.T) {
	fieldErrs := []FieldError{{Field: "name", Tag: "required", Message: "name is required"}}
	ve := NewFieldValidationError(fieldErrs)
	fieldErrs[0].Message = "MUTATED-BY-CALLER"
	if got := ve.Error(); got != "name is required" {
		t.Fatalf("Error() = %q, 入参事后改写不得影响错误值（#116 修复前为 MUTATED-BY-CALLER）", got)
	}
	if got := ve.Map()["name"]; got != "name is required" {
		t.Fatalf("Map()[name] = %q, want 不受入参改写影响", got)
	}
	if got := ve.Errors()[0].Message; got != "name is required" {
		t.Fatalf("Errors()[0].Message = %q, want 不受入参改写影响", got)
	}
}

// #116：Errors() 返回副本——审计组件拿 Errors() 后排序/改写 Message（常见形态）
// 不得污染 Error()/Map()/String()；跨 goroutine 异步上报时双向别名还会构成数据
// 竞争。修复前断言失败：Map() 跟着返回值改写变成 HACKED。
func TestValidationError_ErrorsReturnsCopy(t *testing.T) {
	ve := NewFieldValidationError([]FieldError{{Field: "name", Tag: "required", Message: "name is required"}})
	got := ve.Errors()
	got[0].Message = "HACKED"
	if got := ve.Error(); got != "name is required" {
		t.Fatalf("Error() = %q, Errors() 改写不得污染错误值（#116 修复前为 HACKED）", got)
	}
	if m := ve.Map()["name"]; m != "name is required" {
		t.Fatalf("Map()[name] = %q, Errors() 改写不得污染 Map()", m)
	}
	if s := ve.String(); s != "validation failed: name (required)" {
		t.Fatalf("String() = %q, want 不受 Errors() 改写影响", s)
	}
	// 返回值是独立副本：长度/元素与内部一致，但底层数组不共享。
	if len(got) != 1 || got[0].Field != "name" {
		t.Fatalf("Errors() = %+v, want 副本内容与内部一致", got)
	}
	if &got[0] == &ve.errors[0] {
		t.Fatal("Errors() 必须返回副本（底层数组不得与内部共享）")
	}
}
