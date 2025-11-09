// Package logger 提供基于logrus的日志工具
// 支持控制台颜色输出和快捷方法
// 使用示例：
//
//	logger.Init()                    // 使用默认Debug级别初始化
//	logger.Init(logrus.InfoLevel)    // 使用Info级别初始化
//	logger.Info("这是一条信息日志")
//	logger.Infof("用户 %s 登录", "张三")
//	logger.WithField("user", "李四").Info("用户操作")
package logger

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

var (
	// log 全局日志实例
	log *logrus.Logger
)

// Init 初始化日志配置
// level: 可选的日志级别，默认为DebugLevel
func Init(level ...logrus.Level) {
	log = logrus.New()

	// 设置输出到控制台
	log.SetOutput(os.Stdout)

	// 设置日志格式为文本格式
	log.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,                  // 强制颜色输出
		FullTimestamp:   true,                  // 显示完整时间戳
		TimestampFormat: "2006-01-02 15:04:05", // 时间格式
		DisableQuote:    true,                  // 禁用引号
	})

	// 设置日志级别
	if len(level) > 0 {
		log.SetLevel(level[0])
	} else {
		log.SetLevel(logrus.DebugLevel) // 默认Debug级别
	}
}

// SetOutput 设置日志输出
func SetOutput(output io.Writer) {
	GetLogger().SetOutput(output)
}

// GetLogger 获取日志实例
func GetLogger() *logrus.Logger {
	if log == nil {
		Init()
	}
	return log
}

// SetLevel 设置日志级别
func SetLevel(level logrus.Level) {
	GetLogger().SetLevel(level)
}

// SetFormatter 设置日志格式
func SetFormatter(formatter logrus.Formatter) {
	GetLogger().SetFormatter(formatter)
}

// Debug 调试日志
func Debug(args ...interface{}) {
	GetLogger().Debug(args...)
}

// Debugf 格式化调试日志
func Debugf(format string, args ...interface{}) {
	GetLogger().Debugf(format, args...)
}

// Info 信息日志
func Info(args ...interface{}) {
	GetLogger().Info(args...)
}

// Infof 格式化信息日志
func Infof(format string, args ...interface{}) {
	GetLogger().Infof(format, args...)
}

// Warn 警告日志
func Warn(args ...interface{}) {
	GetLogger().Warn(args...)
}

// Warnf 格式化警告日志
func Warnf(format string, args ...interface{}) {
	GetLogger().Warnf(format, args...)
}

// Error 错误日志
func Error(args ...interface{}) {
	GetLogger().Error(args...)
}

// Errorf 格式化错误日志
func Errorf(format string, args ...interface{}) {
	GetLogger().Errorf(format, args...)
}

// Fatal 致命错误日志（会退出程序）
func Fatal(args ...interface{}) {
	GetLogger().Fatal(args...)
}

// Fatalf 格式化致命错误日志（会退出程序）
func Fatalf(format string, args ...interface{}) {
	GetLogger().Fatalf(format, args...)
}

// Panic 恐慌日志（会触发panic）
func Panic(args ...interface{}) {
	GetLogger().Panic(args...)
}

// Panicf 格式化恐慌日志（会触发panic）
func Panicf(format string, args ...interface{}) {
	GetLogger().Panicf(format, args...)
}

// WithField 添加单个字段
func WithField(key string, value interface{}) *logrus.Entry {
	return GetLogger().WithField(key, value)
}

// WithFields 添加多个字段
func WithFields(fields logrus.Fields) *logrus.Entry {
	return GetLogger().WithFields(fields)
}

// WithError 添加错误字段
func WithError(err error) *logrus.Entry {
	return GetLogger().WithError(err)
}
