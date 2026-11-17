package validator

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	bizerrors "github.com/oekit/pkg/errors"
)

// ErrNilValidationFunc 表示注册自定义验证规则时传入了 nil 函数（#94）。
// 注册期显式拦下而非推迟到校验期才炸出 nil 指针 panic——上游
// go-playground/validator 的 fn==nil 守卫会被门面的包装闭包绕过
// （闭包本身永不为 nil），门面必须自己再挡一道。
var ErrNilValidationFunc = errors.New("validator: validation func must not be nil")

// ErrTranslationNotSupported 表示当前验证器不支持错误消息翻译。
// PlaygroundValidator 的错误消息已通过 formatMessageNamed 内置英文提示，
// 如需自定义消息请扩展 formatMessageNamed 或实现自定义 Validator。
var ErrTranslationNotSupported = errors.New("validator: translation not supported; messages are built-in via formatMessageNamed")

// ErrValidation 是 ValidationError 的包级缓存 BizError 载体（BizCode=400,
// HTTPCode=400）：errors.Is(err, ErrValidation) 判定「校验失败类业务错误」
// 的单点入口（#208）。此前 Unwrap 每次现场 new BizError，errors.Is 对任何
// 具体 BizError 实例永不匹配——包级缓存载体给了调用方可引用的判定目标。
//
// 本载体只承担身份判定，message 是兜底文案；响应语义以 Unwrap 链上携带
// 真实字段消息的载体为准（见 ValidationError.Unwrap）。
var ErrValidation = bizerrors.NewBizErrorWithStatus(400, 400, "validation failed")

// ValidationError 包含多个字段验证错误。
// 实现 BizError 接口（code=400），handler 层的 Fail 会自动识别为 400 Bad Request。
type ValidationError struct {
	errors []FieldError

	// bizOnce/bizErr 缓存 Unwrap 载体（#208）：sync.Once 零值即可用（直接
	// 构造 &ValidationError{} 的路径同样生效），同一错误值反复 Unwrap 返回
	// 同一实例——errors.Is 对该实例的判定从此稳定。
	bizOnce sync.Once
	bizErr  *bizerrors.BizError
}

// FieldError 表示单个字段的验证错误。
type FieldError struct {
	Field   string `json:"field"`           // 字段名
	Tag     string `json:"tag"`             // 验证标签
	Param   string `json:"param,omitempty"` // 标签参数
	Message string `json:"message"`         // 错误消息
}

// Error 实现 error 接口，返回第一个错误消息。
func (e *ValidationError) Error() string {
	if len(e.errors) == 0 {
		return "validation failed"
	}
	return e.errors[0].Message
}

// Unwrap 返回本错误值缓存的 BizError 载体（BizCode=400, HTTPCode=400），使
// errors.As 能识别为 BizError——这样 handler 层的 Fail 会自动返回 400 Bad
// Request，而非 500。
//
// #208：载体经 sync.Once 构造一次并缓存于错误值自身（同一错误值反复 Unwrap
// 返回同一实例），不再是每次现场 new——此前每次身份都不同，errors.Is 对任何
// 具体 BizError 实例永不匹配。message 保真仍取首条字段消息：middleware.Fail
// 响应体直接渲染 BizError.Message，换成包级静态文案会让 API 消费方丢掉
// 「哪个字段为什么没过」；errors.Is(err, ErrValidation) 的身份判定由 Is 桥接
// 到包级缓存载体。
func (e *ValidationError) Unwrap() error {
	e.bizOnce.Do(func() {
		e.bizErr = bizerrors.NewBizErrorWithStatus(400, 400, e.Error())
	})
	return e.bizErr
}

// Is 把包级缓存载体 ErrValidation 桥接进 errors.Is 的判定（#208）：errors.Is
// 对链上每个错误先做相等比较、再询问本方法——无需把载体挂进 Unwrap 链
// （挂链会让 middleware.Fail 的 cause 落日志把每个 400 判成 error noise，
// 也会让响应 message 退化为静态文案）。仅恒等匹配 ErrValidation；其余目标
// （含其它 400 码 BizError 实例）一律 false，不放大判定语义。
func (e *ValidationError) Is(target error) bool {
	return target == ErrValidation
}

// Errors 返回所有字段错误（副本，#116）：返回值与内部存储不共享底层数组——
// 调用方排序/改写返回值不得影响错误值自身的 Error()/Map()/String()。错误值在
// Go 里按惯例不可变（core#80 同款快照纪律：已发布的快照不可被事后改写）。
func (e *ValidationError) Errors() []FieldError {
	return slices.Clone(e.errors)
}

// Map 返回 field→message 映射，适用于 JSON 响应。
func (e *ValidationError) Map() map[string]string {
	m := make(map[string]string, len(e.errors))
	for _, fe := range e.errors {
		m[fe.Field] = fe.Message
	}
	return m
}

// Len 返回错误数量。
func (e *ValidationError) Len() int {
	return len(e.errors)
}

// String 实现 fmt.Stringer。
func (e *ValidationError) String() string {
	var sb strings.Builder
	sb.WriteString("validation failed: ")
	for i, fe := range e.errors {
		if i > 0 {
			sb.WriteString("; ")
		}
		fmt.Fprintf(&sb, "%s (%s)", fe.Field, fe.Tag)
	}
	return sb.String()
}

// NewFieldValidationError 创建包含指定字段错误的验证错误（构造期拷贝入参，
// #116）。供 handler/validatorh 等外部包构造 ValidationError。入参与内部存储
// 不共享底层数组（slices.Clone）——调用方构造后复用底层数组做日志增强/翻译
// 不得让已返回给调用方的错误值内容事后漂移（构造与 Errors() 读取双向别名在
// 此切断，core#80 同构）。
func NewFieldValidationError(fieldErrs []FieldError) *ValidationError {
	return &ValidationError{errors: slices.Clone(fieldErrs)}
}

// IsValidationError 检查错误是否为 ValidationError 类型。
func IsValidationError(err error) bool {
	_, ok := AsValidationError(err)
	return ok
}

// AsValidationError 从错误链中提取 ValidationError（支持 errors.As 链式匹配）。
func AsValidationError(err error) (*ValidationError, bool) {
	if err == nil {
		return nil, false
	}
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}
