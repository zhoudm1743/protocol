package sse

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"protocol/pkg/eventbus"
	"protocol/pkg/logger"
)

// SSEClient SSE客户端
type SSEClient struct {
	UserID   uint
	TenantID uint
	Writer   http.ResponseWriter
	Flusher  http.Flusher
	Done     chan struct{}
	mu       sync.Mutex
}

// Send 发送消息给客户端
func (c *SSEClient) Send(event string, data string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.Done:
		return fmt.Errorf("client disconnected")
	default:
		if _, err := fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, data); err != nil {
			return err
		}
		c.Flusher.Flush()
		return nil
	}
}

// Close 关闭客户端连接
func (c *SSEClient) Close() {
	close(c.Done)
}

// SSEManager SSE连接管理器
type SSEManager struct {
	clients map[uint]map[uint]*SSEClient // tenantID -> userID -> client
	mu      sync.RWMutex
	bus     *eventbus.EventBus
}

var (
	defaultManager *SSEManager
	managerOnce    sync.Once
)

// GetDefaultManager 获取默认SSE管理器（单例）
func GetDefaultManager() *SSEManager {
	managerOnce.Do(func() {
		defaultManager = NewSSEManager(eventbus.GetDefaultBus())
	})
	return defaultManager
}

// NewSSEManager 创建SSE管理器
func NewSSEManager(bus *eventbus.EventBus) *SSEManager {
	manager := &SSEManager{
		clients: make(map[uint]map[uint]*SSEClient),
		bus:     bus,
	}

	logger.Info("[SSEManager] SSE管理器已初始化")
	return manager
}

// AddClient 添加客户端
func (m *SSEManager) AddClient(userID, tenantID uint, w http.ResponseWriter) (*SSEClient, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("streaming not supported")
	}

	client := &SSEClient{
		UserID:   userID,
		TenantID: tenantID,
		Writer:   w,
		Flusher:  flusher,
		Done:     make(chan struct{}),
	}

	m.mu.Lock()
	if m.clients[tenantID] == nil {
		m.clients[tenantID] = make(map[uint]*SSEClient)
	}
	// 如果已有连接，先关闭旧连接
	if oldClient, exists := m.clients[tenantID][userID]; exists {
		oldClient.Close()
	}
	m.clients[tenantID][userID] = client
	m.mu.Unlock()

	logger.Infof("[SSEManager] 添加客户端: UserID=%d, TenantID=%d (总连接数: %d)",
		userID, tenantID, m.GetClientCount())
	return client, nil
}

// RemoveClient 移除客户端
func (m *SSEManager) RemoveClient(userID, tenantID uint) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if tenantClients, exists := m.clients[tenantID]; exists {
		if client, exists := tenantClients[userID]; exists {
			client.Close()
			delete(tenantClients, userID)
			if len(tenantClients) == 0 {
				delete(m.clients, tenantID)
			}
			logger.Infof("[SSEManager] 移除客户端: UserID=%d, TenantID=%d (剩余连接数: %d)",
				userID, tenantID, m.GetClientCount())
		}
	}
}

// GetClient 获取客户端
func (m *SSEManager) GetClient(userID, tenantID uint) (*SSEClient, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if tenantClients, exists := m.clients[tenantID]; exists {
		client, exists := tenantClients[userID]
		return client, exists
	}
	return nil, false
}

// SendToUser 发送消息给指定用户
func (m *SSEManager) SendToUser(userID, tenantID uint, event, data string) error {
	client, exists := m.GetClient(userID, tenantID)
	if !exists {
		return fmt.Errorf("client not found: UserID=%d, TenantID=%d", userID, tenantID)
	}

	return client.Send(event, data)
}

// BroadcastToTenant 广播消息给租户下的所有用户
func (m *SSEManager) BroadcastToTenant(tenantID uint, event, data string) {
	m.mu.RLock()
	clients := make([]*SSEClient, 0)
	if tenantClients, exists := m.clients[tenantID]; exists {
		for _, client := range tenantClients {
			clients = append(clients, client)
		}
	}
	m.mu.RUnlock()

	for _, client := range clients {
		if err := client.Send(event, data); err != nil {
			logger.Errorf("[SSEManager] 发送失败: UserID=%d, Error=%v", client.UserID, err)
			// 发送失败，移除客户端
			m.RemoveClient(client.UserID, client.TenantID)
		}
	}
}

// GetClientCount 获取当前连接数
func (m *SSEManager) GetClientCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, tenantClients := range m.clients {
		count += len(tenantClients)
	}
	return count
}

// GetTenantClientCount 获取租户的连接数
func (m *SSEManager) GetTenantClientCount(tenantID uint) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if tenantClients, exists := m.clients[tenantID]; exists {
		return len(tenantClients)
	}
	return 0
}

// KeepAlive 保持连接（发送心跳）
func (m *SSEManager) KeepAlive() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.RLock()
		allClients := make([]*SSEClient, 0)
		for _, tenantClients := range m.clients {
			for _, client := range tenantClients {
				allClients = append(allClients, client)
			}
		}
		m.mu.RUnlock()

		for _, client := range allClients {
			if err := client.Send("heartbeat", `{"ping":"pong"}`); err != nil {
				// 心跳失败，移除客户端
				m.RemoveClient(client.UserID, client.TenantID)
			}
		}
	}
}

// Start 启动SSE管理器（启动心跳）
func (m *SSEManager) Start() {
	go m.KeepAlive()
	logger.Info("[SSEManager] SSE管理器已启动")
}
