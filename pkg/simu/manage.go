package simu

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"protocol/pkg/logger"
	"protocol/utils"
)

// ProtocolHandler 协议处理器接口
type ProtocolHandler interface {
	// ParseRequest 解析请求帧
	ParseRequest(data []byte) (interface{}, error)
	// BuildReply 构建应答帧
	BuildReply(request interface{}, config *DeviceConfig) ([]byte, error)
	// ValidateAddress 验证地址是否匹配（支持单地址或双地址）
	ValidateAddress(request interface{}, config *DeviceConfig) bool
	// BuildReport 构建主动上报帧（支持主动上报的协议实现此方法）
	BuildReport(config *DeviceConfig, reportType string, data map[string]interface{}) ([]byte, error)
	// GetAddresses 获取设备地址（返回主地址和从地址，单地址协议返回主地址，从地址为空）
	GetAddresses(config *DeviceConfig) (primaryAddr string, secondaryAddr string)
	// SupportActiveReport 是否支持主动上报
	SupportActiveReport() bool
	// HandleCommand 处理控制指令（如开关阀等），返回是否成功和状态变化
	HandleCommand(request interface{}, config *DeviceConfig, state *DeviceState) (success bool, stateChanges map[string]interface{}, reply []byte, err error)
	// GetCommandInfo 获取指令信息（用于显示）
	GetCommandInfo(request interface{}) (commandType string, commandDesc string)
}

// DeviceConfig 设备配置
type DeviceConfig struct {
	ProtocolType string                 // 协议类型: cj188/cat1/3761/modbus/dlt645
	Config       map[string]interface{} // 协议特定配置（JSON格式，由各协议自行解析）
}

// DeviceState 设备状态（通用状态存储，支持不同协议的各种状态字段）
// 使用map存储状态，支持：
// - CJ188: valveStatus(int), batteryStatus(bool), it05Status(bool), alarmStatus(int), flowData(uint32)
// - 3761/CAT.1: signalStatus(int), imei(string), powerConsumption(float64), voltage(float64) 等
type DeviceState struct {
	state map[string]interface{} // 状态字段映射，key为字段名，value为任意类型
	mu    sync.RWMutex
}

// NewDeviceState 创建设备状态
func NewDeviceState() *DeviceState {
	return &DeviceState{
		state: make(map[string]interface{}),
	}
}

// Get 获取状态值
func (s *DeviceState) Get(key string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, exists := s.state[key]
	return value, exists
}

// Set 设置状态值
func (s *DeviceState) Set(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state[key] = value
}

// GetString 获取字符串类型状态值（如IMEI）
func (s *DeviceState) GetString(key string) (string, bool) {
	value, exists := s.Get(key)
	if !exists {
		return "", false
	}
	if str, ok := value.(string); ok {
		return str, true
	}
	return fmt.Sprintf("%v", value), true
}

// GetInt 获取整数类型状态值（如阀门状态、信号状态）
func (s *DeviceState) GetInt(key string) (int, bool) {
	value, exists := s.Get(key)
	if !exists {
		return 0, false
	}
	switch v := value.(type) {
	case int:
		return v, true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}

// GetUint32 获取uint32类型状态值（如累积流量）
func (s *DeviceState) GetUint32(key string) (uint32, bool) {
	value, exists := s.Get(key)
	if !exists {
		return 0, false
	}
	switch v := value.(type) {
	case uint32:
		return v, true
	case uint:
		return uint32(v), true
	case uint64:
		return uint32(v), true
	case int:
		if v >= 0 {
			return uint32(v), true
		}
	case int64:
		if v >= 0 {
			return uint32(v), true
		}
	case float64:
		if v >= 0 {
			return uint32(v), true
		}
	}
	return 0, false
}

// GetFloat64 获取float64类型状态值（用于用电量、电压等）
func (s *DeviceState) GetFloat64(key string) (float64, bool) {
	value, exists := s.Get(key)
	if !exists {
		return 0, false
	}
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	default:
		return 0, false
	}
}

// GetBool 获取布尔类型状态值（如电池状态）
func (s *DeviceState) GetBool(key string) (bool, bool) {
	value, exists := s.Get(key)
	if !exists {
		return false, false
	}
	if b, ok := value.(bool); ok {
		return b, true
	}
	return false, false
}

// GetAll 获取所有状态
func (s *DeviceState) GetAll() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]interface{})
	for k, v := range s.state {
		result[k] = v
	}
	return result
}

// GetStatusByte 获取状态字节（CJ188协议专用，根据状态字段计算状态字节）
func (s *DeviceState) GetStatusByte() byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var status byte

	// D0-D1: 阀门状态
	if valveStatus, ok := s.state["valveStatus"].(int); ok {
		status |= byte(valveStatus & 0x03)
	}

	// D2: 电池状态
	if batteryStatus, ok := s.state["batteryStatus"].(bool); ok && batteryStatus {
		status |= 0x04
	}

	// D6: IT05状态
	if it05Status, ok := s.state["it05Status"].(bool); ok && it05Status {
		status |= 0x40
	}

	// D6-D7: 报警器状态
	if alarmStatus, ok := s.state["alarmStatus"].(int); ok {
		status |= byte((alarmStatus & 0x03) << 6)
	}

	return status
}

// SetEventCallback 设置事件回调
func (d *BaseDevice) SetEventCallback(callback func(eventType string, data map[string]interface{})) {
	d.eventCallback = callback
}

// GetState 获取设备状态
func (d *BaseDevice) GetState() *DeviceState {
	return d.state
}

// Device 模拟设备接口
type Device interface {
	Start() error
	Stop() error
	IsRunning() bool
	GetConfig() *DeviceConfig
}

// Manager 模拟器管理器
type Manager struct {
	devices          map[string]Device
	protocolHandlers map[string]ProtocolHandler
	mu               sync.RWMutex
	protocolMu       sync.RWMutex
}

var defaultManager *Manager
var managerOnce sync.Once

// GetDefaultManager 获取默认管理器
func GetDefaultManager() *Manager {
	managerOnce.Do(func() {
		defaultManager = &Manager{
			devices:          make(map[string]Device),
			protocolHandlers: make(map[string]ProtocolHandler),
		}
	})
	return defaultManager
}

// RegisterProtocolHandler 注册协议处理器
func (m *Manager) RegisterProtocolHandler(protocolType string, handler ProtocolHandler) {
	m.protocolMu.Lock()
	defer m.protocolMu.Unlock()
	m.protocolHandlers[protocolType] = handler
	logger.Infof("[模拟器管理器] 注册协议处理器: %s", protocolType)
}

// GetProtocolHandler 获取协议处理器
func (m *Manager) GetProtocolHandler(protocolType string) (ProtocolHandler, error) {
	m.protocolMu.RLock()
	defer m.protocolMu.RUnlock()
	handler, exists := m.protocolHandlers[protocolType]
	if !exists {
		return nil, fmt.Errorf("协议处理器不存在: %s", protocolType)
	}
	return handler, nil
}

// AddDevice 添加设备
func (m *Manager) AddDevice(id string, device Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.devices[id]; exists {
		return fmt.Errorf("设备已存在: %s", id)
	}
	m.devices[id] = device
	return nil
}

// RemoveDevice 移除设备
func (m *Manager) RemoveDevice(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	device, exists := m.devices[id]
	if !exists {
		return fmt.Errorf("设备不存在: %s", id)
	}
	if device.IsRunning() {
		device.Stop()
	}
	delete(m.devices, id)
	return nil
}

// GetDevice 获取设备
func (m *Manager) GetDevice(id string) (Device, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	device, exists := m.devices[id]
	return device, exists
}

// ListDevices 列出所有设备
func (m *Manager) ListDevices() map[string]Device {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]Device)
	for id, device := range m.devices {
		result[id] = device
	}
	return result
}

// BaseDevice 基础设备结构（包含协议处理逻辑）
type BaseDevice struct {
	config         *DeviceConfig
	manager        *Manager
	state          *DeviceState  // 设备状态
	reportInterval time.Duration // 主动上报间隔（0表示不上报）
	reportEnabled  bool          // 是否启用主动上报
	reportChan     chan struct{} // 上报触发通道
	reportMu       sync.RWMutex
	eventCallback  func(eventType string, data map[string]interface{}) // 事件回调函数
}

// handleRequest 处理请求（通用方法）
func (d *BaseDevice) handleRequest(data []byte) ([]byte, error) {
	// 获取协议处理器
	handler, err := d.manager.GetProtocolHandler(d.config.ProtocolType)
	if err != nil {
		return nil, fmt.Errorf("获取协议处理器失败: %v", err)
	}

	// 解析请求
	request, err := handler.ParseRequest(data)
	if err != nil {
		return nil, fmt.Errorf("解析请求失败: %v", err)
	}

	// 验证地址
	if !handler.ValidateAddress(request, d.config) {
		return nil, fmt.Errorf("地址验证失败")
	}

	// 获取指令信息
	commandType, commandDesc := handler.GetCommandInfo(request)

	// 发布接收指令事件
	if d.eventCallback != nil {
		d.eventCallback("command_received", map[string]interface{}{
			"commandType": commandType,
			"commandDesc": commandDesc,
			"hexData":     utils.HexTool.ToHexString(data),
		})
	}

	// 尝试处理控制指令（如开关阀等）
	success, stateChanges, reply, err := handler.HandleCommand(request, d.config, d.state)
	if err == nil && success {
		// 更新设备状态（通用更新，支持任意字段）
		if stateChanges != nil {
			for key, value := range stateChanges {
				d.state.Set(key, value)
			}

			// 发布状态变化事件
			if d.eventCallback != nil {
				d.eventCallback("state_changed", map[string]interface{}{
					"commandType": commandType,
					"commandDesc": commandDesc,
					"changes":     stateChanges,
				})
			}
		}

		if reply != nil {
			return reply, nil
		}
	}

	// 如果不是控制指令或处理失败，按查询指令处理
	// 将设备状态传递给配置（用于BuildReply）
	d.config.Config["_deviceState"] = d.state

	reply, err = handler.BuildReply(request, d.config)
	if err != nil {
		return nil, fmt.Errorf("构建应答失败: %v", err)
	}

	// 发布应答事件
	if d.eventCallback != nil {
		d.eventCallback("reply_sent", map[string]interface{}{
			"commandType": commandType,
			"hexData":     utils.HexTool.ToHexString(reply),
		})
	}

	return reply, nil
}

// startActiveReport 启动主动上报（如果协议支持）
func (d *BaseDevice) startActiveReport(sendFunc func([]byte) error) {
	handler, err := d.manager.GetProtocolHandler(d.config.ProtocolType)
	if err != nil || !handler.SupportActiveReport() {
		return
	}

	d.reportMu.RLock()
	enabled := d.reportEnabled
	interval := d.reportInterval
	d.reportMu.RUnlock()

	if !enabled || interval <= 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-d.reportChan:
				return
			case <-ticker.C:
				// 构建上报帧
				reportData, err := handler.BuildReport(d.config, "periodic", nil)
				if err != nil {
					logger.Errorf("[主动上报] 构建上报帧失败: %v", err)
					continue
				}

				// 发送上报
				if err := sendFunc(reportData); err != nil {
					logger.Errorf("[主动上报] 发送上报失败: %v", err)
				} else {
					logger.Infof("[主动上报] 已发送上报: %s", utils.HexTool.ToHexString(reportData))
				}
			}
		}
	}()
}

// triggerReport 触发一次主动上报
func (d *BaseDevice) triggerReport(sendFunc func([]byte) error, reportType string, data map[string]interface{}) error {
	handler, err := d.manager.GetProtocolHandler(d.config.ProtocolType)
	if err != nil || !handler.SupportActiveReport() {
		return fmt.Errorf("协议不支持主动上报")
	}

	reportData, err := handler.BuildReport(d.config, reportType, data)
	if err != nil {
		return fmt.Errorf("构建上报帧失败: %v", err)
	}

	return sendFunc(reportData)
}

// setReportConfig 设置上报配置
func (d *BaseDevice) setReportConfig(enabled bool, interval time.Duration) {
	d.reportMu.Lock()
	defer d.reportMu.Unlock()
	d.reportEnabled = enabled
	d.reportInterval = interval
	if d.reportChan == nil {
		d.reportChan = make(chan struct{})
	}
}

// SerialDevice 串口设备
type SerialDevice struct {
	BaseDevice
	port     string
	baudRate int
	running  bool
	stopChan chan struct{}
	mu       sync.RWMutex
}

// NewSerialDevice 创建串口设备
func NewSerialDevice(config *DeviceConfig, port string, baudRate int, manager *Manager) *SerialDevice {
	return &SerialDevice{
		BaseDevice: BaseDevice{
			config:  config,
			manager: manager,
		},
		port:     port,
		baudRate: baudRate,
		stopChan: make(chan struct{}),
	}
}

// GetConfig 获取配置
func (d *SerialDevice) GetConfig() *DeviceConfig {
	return d.config
}

// IsRunning 是否运行中
func (d *SerialDevice) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running
}

// Start 启动串口设备
func (d *SerialDevice) Start() error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("设备已在运行中")
	}
	d.running = true
	d.mu.Unlock()

	logger.Infof("[串口设备] 启动串口设备: %s, 波特率: %d, 协议: %s", d.port, d.baudRate, d.config.ProtocolType)
	// TODO: 实现串口通信
	// 这里需要使用串口库，例如 go.bug.st/serial
	logger.Warnf("[串口设备] 串口功能需要安装串口库，当前未实现")
	return nil
}

// Stop 停止串口设备
func (d *SerialDevice) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.running {
		return fmt.Errorf("设备未运行")
	}
	d.running = false
	close(d.stopChan)
	d.stopChan = make(chan struct{})
	logger.Infof("[串口设备] 串口设备已停止: %s", d.port)
	return nil
}

// TCPServerDevice TCP服务器设备（从机）
type TCPServerDevice struct {
	BaseDevice
	address  string
	listener net.Listener
	running  bool
	stopChan chan struct{}
	mu       sync.RWMutex
	conns    map[string]net.Conn
	connsMu  sync.RWMutex
}

// NewTCPServerDevice 创建TCP服务器设备
func NewTCPServerDevice(config *DeviceConfig, address string, manager *Manager) *TCPServerDevice {
	return &TCPServerDevice{
		BaseDevice: BaseDevice{
			config:     config,
			manager:    manager,
			state:      NewDeviceState(),
			reportChan: make(chan struct{}),
		},
		address:  address,
		stopChan: make(chan struct{}),
		conns:    make(map[string]net.Conn),
	}
}

// GetConfig 获取配置
func (d *TCPServerDevice) GetConfig() *DeviceConfig {
	return d.config
}

// IsRunning 是否运行中
func (d *TCPServerDevice) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running
}

// Start 启动TCP服务器设备
func (d *TCPServerDevice) Start() error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("设备已在运行中")
	}
	d.running = true
	d.mu.Unlock()

	// 处理地址格式：如果只输入了端口号，监听所有接口
	address := d.address
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// 如果地址格式不正确，尝试作为端口号处理
		address = "0.0.0.0:" + address
	} else {
		// 如果只输入了端口号（host为空），监听所有接口
		if host == "" {
			address = "0.0.0.0:" + port
		} else {
			// 验证IP地址是否有效
			ip := net.ParseIP(host)
			if ip == nil {
				// IP地址无效，尝试使用0.0.0.0
				logger.Warnf("[TCP服务器设备] IP地址无效: %s，使用0.0.0.0代替", host)
				address = "0.0.0.0:" + port
			}
		}
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
		// 如果绑定失败，尝试使用0.0.0.0
		if !strings.HasPrefix(address, "0.0.0.0:") {
			logger.Warnf("[TCP服务器设备] 绑定地址失败: %s，尝试使用0.0.0.0", address)
			_, port, _ := net.SplitHostPort(address)
			if port != "" {
				address = "0.0.0.0:" + port
				listener, err = net.Listen("tcp", address)
			}
		}
		if err != nil {
			return fmt.Errorf("监听TCP地址失败: %v (尝试监听: %s)", err, address)
		}
	}
	d.listener = listener
	d.address = address // 更新为实际监听的地址

	logger.Infof("[TCP服务器设备] 启动TCP服务器: %s, 协议: %s", d.address, d.config.ProtocolType)

	// 检查并配置主动上报（上报将在每个连接中启动）
	if reportInterval, ok := d.config.Config["reportInterval"].(float64); ok && reportInterval > 0 {
		interval := time.Duration(reportInterval) * time.Second
		d.setReportConfig(true, interval)
	}

	go d.acceptConnections()

	return nil
}

// acceptConnections 接受连接
func (d *TCPServerDevice) acceptConnections() {
	for {
		select {
		case <-d.stopChan:
			return
		default:
			conn, err := d.listener.Accept()
			if err != nil {
				select {
				case <-d.stopChan:
					return
				default:
					logger.Errorf("[TCP服务器设备] 接受连接失败: %v", err)
					continue
				}
			}

			connID := conn.RemoteAddr().String()
			logger.Infof("[TCP服务器设备] 新连接: %s", connID)

			d.connsMu.Lock()
			d.conns[connID] = conn
			d.connsMu.Unlock()

			go d.handleConnection(connID, conn)
		}
	}
}

// handleConnection 处理连接
func (d *TCPServerDevice) handleConnection(connID string, conn net.Conn) {
	// 为每个连接启动主动上报（如果协议支持）
	d.startActiveReport(func(data []byte) error {
		_, err := conn.Write(data)
		return err
	})
	defer func() {
		conn.Close()
		d.connsMu.Lock()
		delete(d.conns, connID)
		d.connsMu.Unlock()
		logger.Infof("[TCP服务器设备] 连接已关闭: %s", connID)
	}()

	buffer := make([]byte, 4096)
	for {
		select {
		case <-d.stopChan:
			return
		default:
			// 设置读取超时
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))

			// 读取数据
			n, err := conn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					logger.Errorf("[TCP服务器设备] 读取数据失败: %v", err)
				}
				return
			}

			if n == 0 {
				continue
			}

			// 处理请求
			reply, err := d.handleRequest(buffer[:n])
			if err != nil {
				logger.Errorf("[TCP服务器设备] 处理请求失败: %v", err)
				continue
			}

			// 发送应答
			if reply != nil {
				_, err = conn.Write(reply)
				if err != nil {
					logger.Errorf("[TCP服务器设备] 发送应答失败: %v", err)
					return
				}
				logger.Infof("[TCP服务器设备] 已发送应答: %s", utils.HexTool.ToHexString(reply))
			}
		}
	}
}

// Stop 停止TCP服务器设备
func (d *TCPServerDevice) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.running {
		return fmt.Errorf("设备未运行")
	}
	d.running = false
	close(d.stopChan)
	d.stopChan = make(chan struct{})
	// 关闭上报通道
	if d.reportChan != nil {
		close(d.reportChan)
		d.reportChan = make(chan struct{})
	}

	// 关闭所有连接
	d.connsMu.Lock()
	for connID, conn := range d.conns {
		conn.Close()
		delete(d.conns, connID)
	}
	d.connsMu.Unlock()

	// 关闭监听器
	if d.listener != nil {
		d.listener.Close()
	}

	logger.Infof("[TCP服务器设备] TCP服务器已停止: %s", d.address)
	return nil
}

// TCPClientDevice TCP客户端设备（从机）
type TCPClientDevice struct {
	BaseDevice
	address   string
	conn      net.Conn
	running   bool
	stopChan  chan struct{}
	mu        sync.RWMutex
	reconnect bool
}

// NewTCPClientDevice 创建TCP客户端设备
func NewTCPClientDevice(config *DeviceConfig, address string, reconnect bool, manager *Manager) *TCPClientDevice {
	return &TCPClientDevice{
		BaseDevice: BaseDevice{
			config:     config,
			manager:    manager,
			state:      NewDeviceState(),
			reportChan: make(chan struct{}),
		},
		address:   address,
		stopChan:  make(chan struct{}),
		reconnect: reconnect,
	}
}

// GetConfig 获取配置
func (d *TCPClientDevice) GetConfig() *DeviceConfig {
	return d.config
}

// IsRunning 是否运行中
func (d *TCPClientDevice) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running
}

// Start 启动TCP客户端设备
func (d *TCPClientDevice) Start() error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("设备已在运行中")
	}
	d.running = true
	d.mu.Unlock()

	logger.Infof("[TCP客户端设备] 启动TCP客户端: %s, 协议: %s", d.address, d.config.ProtocolType)

	// 检查并启动主动上报
	if reportInterval, ok := d.config.Config["reportInterval"].(float64); ok && reportInterval > 0 {
		interval := time.Duration(reportInterval) * time.Second
		d.setReportConfig(true, interval)
	}

	go d.connectAndServe()

	return nil
}

// connectAndServe 连接并服务
func (d *TCPClientDevice) connectAndServe() {
	for {
		select {
		case <-d.stopChan:
			return
		default:
			// 连接到服务器
			conn, err := net.DialTimeout("tcp", d.address, 5*time.Second)
			if err != nil {
				logger.Errorf("[TCP客户端设备] 连接失败: %v", err)
				if !d.reconnect {
					d.mu.Lock()
					d.running = false
					d.mu.Unlock()
					return
				}
				time.Sleep(3 * time.Second)
				continue
			}

			d.mu.Lock()
			d.conn = conn
			d.mu.Unlock()

			logger.Infof("[TCP客户端设备] 已连接到服务器: %s", d.address)

			// 处理连接
			d.handleConnection(conn)

			// 如果不需要重连，退出
			if !d.reconnect {
				d.mu.Lock()
				d.running = false
				d.mu.Unlock()
				return
			}

			// 等待后重连
			time.Sleep(3 * time.Second)
		}
	}
}

// handleConnection 处理连接
func (d *TCPClientDevice) handleConnection(conn net.Conn) {
	defer conn.Close()

	// 启动主动上报（如果协议支持）
	d.startActiveReport(func(data []byte) error {
		_, err := conn.Write(data)
		return err
	})

	buffer := make([]byte, 4096)
	for {
		select {
		case <-d.stopChan:
			return
		default:
			// 设置读取超时
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))

			// 读取数据
			n, err := conn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					logger.Errorf("[TCP客户端设备] 读取数据失败: %v", err)
				}
				return
			}

			if n == 0 {
				continue
			}

			// 处理请求
			reply, err := d.handleRequest(buffer[:n])
			if err != nil {
				logger.Errorf("[TCP客户端设备] 处理请求失败: %v", err)
				continue
			}

			// 发送应答
			if reply != nil {
				_, err = conn.Write(reply)
				if err != nil {
					logger.Errorf("[TCP客户端设备] 发送应答失败: %v", err)
					return
				}
				logger.Infof("[TCP客户端设备] 已发送应答: %s", utils.HexTool.ToHexString(reply))
			}
		}
	}
}

// Stop 停止TCP客户端设备
func (d *TCPClientDevice) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.running {
		return fmt.Errorf("设备未运行")
	}
	d.running = false
	close(d.stopChan)
	d.stopChan = make(chan struct{})
	// 关闭上报通道
	if d.reportChan != nil {
		close(d.reportChan)
		d.reportChan = make(chan struct{})
	}

	if d.conn != nil {
		d.conn.Close()
		d.conn = nil
	}

	logger.Infof("[TCP客户端设备] TCP客户端已停止: %s", d.address)
	return nil
}
