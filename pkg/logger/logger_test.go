package logger

import (
	"testing"
)

// TestLogger 测试日志功能
func TestLogger(t *testing.T) {
	// 初始化日志
	Init()

	// 测试各种日志级别
	Debug("这是一条调试日志")
	Debugf("这是一条格式化调试日志: %s", "测试")

	Info("这是一条信息日志")
	Infof("这是一条格式化信息日志: %s", "测试")

	Warn("这是一条警告日志")
	Warnf("这是一条格式化警告日志: %s", "测试")

	Error("这是一条错误日志")
	Errorf("这是一条格式化错误日志: %s", "测试")

	// 测试带字段的日志
	WithField("user", "张三").Info("用户登录")
	WithFields(map[string]interface{}{
		"user":  "李四",
		"ip":    "192.168.1.1",
		"level": "info",
	}).Info("用户操作")

	// 测试错误日志
	err := &testError{msg: "测试错误"}
	WithError(err).Error("发生错误")
}

// testError 测试用的错误类型
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}


