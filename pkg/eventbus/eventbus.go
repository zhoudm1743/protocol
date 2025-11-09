package eventbus

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"protocol/pkg/logger"
)

// Event 事件接口
type Event interface {
	// Topic 返回事件主题
	Topic() string
	// Data 返回事件数据
	Data() interface{}
	// Timestamp 返回事件时间戳
	Timestamp() time.Time
}

// BaseEvent 基础事件实现
type BaseEvent struct {
	topic     string
	data      interface{}
	timestamp time.Time
}

func NewEvent(topic string, data interface{}) *BaseEvent {
	return &BaseEvent{
		topic:     topic,
		data:      data,
		timestamp: time.Now(),
	}
}

func (e *BaseEvent) Topic() string {
	return e.topic
}

func (e *BaseEvent) Data() interface{} {
	return e.data
}

func (e *BaseEvent) Timestamp() time.Time {
	return e.timestamp
}

// Handler 事件处理函数
type Handler func(ctx context.Context, event Event) error

// UnsubscribeFunc 取消订阅函数
type UnsubscribeFunc func()

// SubscribeOptions 订阅选项
type SubscribeOptions struct {
	Priority   int           // 优先级（数字越大优先级越高）
	Timeout    time.Duration // 超时时间（0表示无超时）
	MaxRetries int           // 最大重试次数（0表示不重试）
	RetryDelay time.Duration // 重试延迟
}

// DefaultSubscribeOptions 默认订阅选项
var DefaultSubscribeOptions = SubscribeOptions{
	Priority:   0,
	Timeout:    30 * time.Second,
	MaxRetries: 0,
	RetryDelay: 100 * time.Millisecond,
}

// handlerWrapper 处理器包装器
type handlerWrapper struct {
	id         uint64
	handler    Handler
	options    SubscribeOptions
	pattern    string // 订阅的模式（支持通配符）
	isWildcard bool   // 是否是通配符订阅
}

// Metrics 事件总线指标
type Metrics struct {
	TotalPublished uint64 // 总发布数
	TotalDelivered uint64 // 总投递数
	TotalFailed    uint64 // 总失败数
	TotalPanics    uint64 // 总panic数
	TotalRetries   uint64 // 总重试数
}

// EventBus 事件总线
type EventBus struct {
	handlers         map[string][]*handlerWrapper // topic -> handlers
	wildcardHandlers []*handlerWrapper            // 通配符订阅的handlers
	mu               sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
	nextID           uint64  // handler ID 生成器
	metrics          Metrics // 指标统计
}

var (
	defaultBus *EventBus
	once       sync.Once
)

// GetDefaultBus 获取默认事件总线实例（单例）
func GetDefaultBus() *EventBus {
	once.Do(func() {
		defaultBus = NewEventBus()
	})
	return defaultBus
}

// NewEventBus 创建新的事件总线
func NewEventBus() *EventBus {
	ctx, cancel := context.WithCancel(context.Background())
	return &EventBus{
		handlers:         make(map[string][]*handlerWrapper),
		wildcardHandlers: make([]*handlerWrapper, 0),
		ctx:              ctx,
		cancel:           cancel,
		nextID:           0,
	}
}

// matchPattern 匹配通配符模式
// 支持 * 匹配任意字符，? 匹配单个字符
// 例如: "user.*" 匹配 "user.login", "user.logout" 等
func matchPattern(pattern, topic string) bool {
	if pattern == topic {
		return true
	}

	// 简单的通配符匹配
	if strings.Contains(pattern, "*") {
		parts := strings.Split(pattern, "*")
		if len(parts) == 1 {
			return pattern == topic
		}

		// 检查开头
		if !strings.HasPrefix(topic, parts[0]) {
			return false
		}
		topic = topic[len(parts[0]):]

		// 检查中间部分
		for i := 1; i < len(parts)-1; i++ {
			idx := strings.Index(topic, parts[i])
			if idx < 0 {
				return false
			}
			topic = topic[idx+len(parts[i]):]
		}

		// 检查结尾
		return strings.HasSuffix(topic, parts[len(parts)-1])
	}

	return false
}

// Subscribe 订阅事件（使用默认选项）
func (eb *EventBus) Subscribe(topic string, handler Handler) UnsubscribeFunc {
	return eb.SubscribeWithOptions(topic, handler, DefaultSubscribeOptions)
}

// SubscribeWithOptions 订阅事件（带选项）
func (eb *EventBus) SubscribeWithOptions(topic string, handler Handler, options SubscribeOptions) UnsubscribeFunc {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	// 生成唯一ID
	handlerID := atomic.AddUint64(&eb.nextID, 1)

	wrapper := &handlerWrapper{
		id:         handlerID,
		handler:    handler,
		options:    options,
		pattern:    topic,
		isWildcard: strings.Contains(topic, "*"),
	}

	if wrapper.isWildcard {
		// 通配符订阅
		eb.wildcardHandlers = append(eb.wildcardHandlers, wrapper)
		logger.Debugf("[EventBus] 订阅通配符事件: %s (ID: %d, 优先级: %d)", topic, handlerID, options.Priority)
	} else {
		// 精确订阅
		eb.handlers[topic] = append(eb.handlers[topic], wrapper)
		// 按优先级排序
		handlers := eb.handlers[topic]
		for i := len(handlers) - 1; i > 0; i-- {
			if handlers[i].options.Priority > handlers[i-1].options.Priority {
				handlers[i], handlers[i-1] = handlers[i-1], handlers[i]
			} else {
				break
			}
		}
		logger.Debugf("[EventBus] 订阅事件: %s (ID: %d, 优先级: %d, 当前订阅数: %d)", topic, handlerID, options.Priority, len(eb.handlers[topic]))
	}

	// 返回取消订阅函数
	return func() {
		eb.unsubscribeByID(handlerID, topic, wrapper.isWildcard)
	}
}

// unsubscribeByID 根据ID取消订阅
func (eb *EventBus) unsubscribeByID(id uint64, topic string, isWildcard bool) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if isWildcard {
		// 从通配符列表中移除
		for i, wrapper := range eb.wildcardHandlers {
			if wrapper.id == id {
				eb.wildcardHandlers = append(eb.wildcardHandlers[:i], eb.wildcardHandlers[i+1:]...)
				logger.Debugf("[EventBus] 取消通配符订阅: %s (ID: %d)", topic, id)
				return
			}
		}
	} else {
		// 从精确订阅中移除
		handlers := eb.handlers[topic]
		for i, wrapper := range handlers {
			if wrapper.id == id {
				eb.handlers[topic] = append(handlers[:i], handlers[i+1:]...)
				logger.Debugf("[EventBus] 取消订阅: %s (ID: %d, 剩余订阅数: %d)", topic, id, len(eb.handlers[topic]))
				if len(eb.handlers[topic]) == 0 {
					delete(eb.handlers, topic)
				}
				return
			}
		}
	}
}

// Unsubscribe 取消订阅（移除该主题的所有订阅者）
func (eb *EventBus) Unsubscribe(topic string) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	count := len(eb.handlers[topic])
	delete(eb.handlers, topic)
	logger.Debugf("[EventBus] 取消订阅: %s (移除 %d 个订阅者)", topic, count)
}

// executeHandler 执行单个handler，带panic恢复、超时控制和重试
func (eb *EventBus) executeHandler(wrapper *handlerWrapper, event Event) {
	defer func() {
		if r := recover(); r != nil {
			atomic.AddUint64(&eb.metrics.TotalPanics, 1)
			logger.Errorf("[EventBus] Handler panic: %v, topic: %s, handler ID: %d", r, event.Topic(), wrapper.id)
		}
	}()

	var err error
	retries := 0
	maxRetries := wrapper.options.MaxRetries

	for {
		// 创建context（可能带超时）
		var ctx context.Context
		var cancel context.CancelFunc

		if wrapper.options.Timeout > 0 {
			ctx, cancel = context.WithTimeout(context.Background(), wrapper.options.Timeout)
		} else {
			ctx, cancel = context.WithCancel(context.Background())
		}

		// 执行handler
		err = wrapper.handler(ctx, event)
		cancel()

		if err == nil {
			// 成功
			atomic.AddUint64(&eb.metrics.TotalDelivered, 1)
			return
		}

		// 失败，检查是否需要重试
		if retries >= maxRetries {
			atomic.AddUint64(&eb.metrics.TotalFailed, 1)
			logger.Errorf("[EventBus] Handler执行失败: %v, topic: %s, handler ID: %d, 重试次数: %d", err, event.Topic(), wrapper.id, retries)
			return
		}

		// 重试
		retries++
		atomic.AddUint64(&eb.metrics.TotalRetries, 1)
		logger.Warnf("[EventBus] Handler重试 (%d/%d): topic: %s, handler ID: %d, error: %v", retries, maxRetries, event.Topic(), wrapper.id, err)

		if wrapper.options.RetryDelay > 0 {
			time.Sleep(wrapper.options.RetryDelay)
		}
	}
}

// getMatchingHandlers 获取匹配的handlers（精确+通配符）
func (eb *EventBus) getMatchingHandlers(topic string) []*handlerWrapper {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	var result []*handlerWrapper

	// 精确匹配的handlers
	if handlers, ok := eb.handlers[topic]; ok {
		result = append(result, handlers...)
	}

	// 通配符匹配的handlers
	for _, wrapper := range eb.wildcardHandlers {
		if matchPattern(wrapper.pattern, topic) {
			result = append(result, wrapper)
		}
	}

	// 按优先级排序所有handlers
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].options.Priority > result[i].options.Priority {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}

// Publish 发布事件（同步）
func (eb *EventBus) Publish(event Event) {
	atomic.AddUint64(&eb.metrics.TotalPublished, 1)

	handlers := eb.getMatchingHandlers(event.Topic())

	if len(handlers) == 0 {
		return
	}

	logger.Debugf("[EventBus] 发布事件: %s (订阅者数: %d)", event.Topic(), len(handlers))

	for _, wrapper := range handlers {
		eb.executeHandler(wrapper, event)
	}
}

// PublishAsync 异步发布事件
func (eb *EventBus) PublishAsync(event Event) {
	go eb.Publish(event)
}

// Close 关闭事件总线
func (eb *EventBus) Close() {
	eb.cancel()
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.handlers = make(map[string][]*handlerWrapper)
	eb.wildcardHandlers = make([]*handlerWrapper, 0)
	logger.Info("[EventBus] 事件总线已关闭")
}

// GetSubscriberCount 获取指定主题的订阅者数量（精确匹配）
func (eb *EventBus) GetSubscriberCount(topic string) int {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return len(eb.handlers[topic])
}

// GetAllTopics 获取所有主题
func (eb *EventBus) GetAllTopics() []string {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	topics := make([]string, 0, len(eb.handlers))
	for topic := range eb.handlers {
		topics = append(topics, topic)
	}
	return topics
}

// GetMetrics 获取事件总线指标
func (eb *EventBus) GetMetrics() Metrics {
	return Metrics{
		TotalPublished: atomic.LoadUint64(&eb.metrics.TotalPublished),
		TotalDelivered: atomic.LoadUint64(&eb.metrics.TotalDelivered),
		TotalFailed:    atomic.LoadUint64(&eb.metrics.TotalFailed),
		TotalPanics:    atomic.LoadUint64(&eb.metrics.TotalPanics),
		TotalRetries:   atomic.LoadUint64(&eb.metrics.TotalRetries),
	}
}

// ResetMetrics 重置指标
func (eb *EventBus) ResetMetrics() {
	atomic.StoreUint64(&eb.metrics.TotalPublished, 0)
	atomic.StoreUint64(&eb.metrics.TotalDelivered, 0)
	atomic.StoreUint64(&eb.metrics.TotalFailed, 0)
	atomic.StoreUint64(&eb.metrics.TotalPanics, 0)
	atomic.StoreUint64(&eb.metrics.TotalRetries, 0)
}

// GetWildcardSubscriberCount 获取通配符订阅者数量
func (eb *EventBus) GetWildcardSubscriberCount() int {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return len(eb.wildcardHandlers)
}

// String 返回指标的字符串表示
func (m Metrics) String() string {
	return fmt.Sprintf("Published: %d, Delivered: %d, Failed: %d, Panics: %d, Retries: %d",
		m.TotalPublished, m.TotalDelivered, m.TotalFailed, m.TotalPanics, m.TotalRetries)
}

// 便捷函数，使用默认事件总线

// Subscribe 订阅事件（使用默认总线）
func Subscribe(topic string, handler Handler) UnsubscribeFunc {
	return GetDefaultBus().Subscribe(topic, handler)
}

// SubscribeWithOptions 订阅事件（使用默认总线，带选项）
func SubscribeWithOptions(topic string, handler Handler, options SubscribeOptions) UnsubscribeFunc {
	return GetDefaultBus().SubscribeWithOptions(topic, handler, options)
}

// Unsubscribe 取消订阅（使用默认总线）
func Unsubscribe(topic string) {
	GetDefaultBus().Unsubscribe(topic)
}

// Publish 发布事件（使用默认总线）
func Publish(event Event) {
	GetDefaultBus().Publish(event)
}

// PublishAsync 异步发布事件（使用默认总线）
func PublishAsync(event Event) {
	GetDefaultBus().PublishAsync(event)
}

// GetMetrics 获取事件总线指标（使用默认总线）
func GetMetrics() Metrics {
	return GetDefaultBus().GetMetrics()
}
