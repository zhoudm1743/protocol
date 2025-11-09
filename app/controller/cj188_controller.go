package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"protocol/app/dto"
	"protocol/pkg/eventbus"
	"protocol/pkg/simu"
	"protocol/protocol/cj188"
	"protocol/utils"

	"context"

	"github.com/gin-gonic/gin"
)

var (
	simulateTasks = make(map[string]*simulateTask)
	simulateMu    sync.RWMutex
)

type simulateTask struct {
	ID       string
	StopChan chan struct{}
	Running  bool
}

// ParseCj188 解析CJ188协议帧
func ParseCj188(c *gin.Context) {
	var req dto.ParseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("参数错误: %v", err),
		})
		return
	}

	// 将十六进制字符串转换为字节数组
	hexData := strings.ReplaceAll(strings.ToUpper(req.HexData), " ", "")
	bytes, err := hexStringToBytes(hexData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("十六进制数据格式错误: %v", err),
		})
		return
	}

	// 解析协议帧
	frame, err := cj188.Parser188(bytes)
	if err != nil {
		c.JSON(http.StatusOK, dto.FrameResponse{
			Success:   false,
			Message:   fmt.Sprintf("解析失败: %v", err),
			Timestamp: time.Now(),
		})
		return
	}

	// 转换为DTO
	frameDTO := dto.ToFrameDTO(frame)
	hexStr := utils.HexTool.ToHexString(bytes)

	// 发布事件到eventbus
	eventData := map[string]interface{}{
		"type":    "parse",
		"frame":   frameDTO,
		"hexData": hexStr,
	}
	eventDataBytes, _ := json.Marshal(eventData)
	eventbus.PublishAsync(eventbus.NewEvent("protocol.cj188.parse", string(eventDataBytes)))

	c.JSON(http.StatusOK, dto.FrameResponse{
		Success:   true,
		Message:   "解析成功",
		HexData:   hexStr,
		Frame:     frameDTO,
		Timestamp: time.Now(),
	})
}

// BuildCj188 构建CJ188协议帧
func BuildCj188(c *gin.Context) {
	var req dto.BuildRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("参数错误: %v", err),
		})
		return
	}

	// 转换数据标识
	dataIDBytes, err := hexStringToBytes(req.DataID)
	if err != nil || len(dataIDBytes) != 2 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "数据标识格式错误，需要4位十六进制字符串（2字节）",
		})
		return
	}

	var frameBytes []byte
	var frame *cj188.Cj188Frame

	// 使用用户指定的序列号（允许为0）
	serial := req.Serial

	// 根据帧类型构建
	switch req.FrameType {
	case "read":
		// 构建查询帧
		frameBytes, err = cj188.Build188(req.MeterType, req.Addr, dataIDBytes, serial)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": fmt.Sprintf("构建查询帧失败: %v", err),
			})
			return
		}
		// 解析构建的帧以获取完整信息
		frame, err = cj188.Parser188(frameBytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": fmt.Sprintf("验证构建的帧失败: %v", err),
			})
			return
		}

	case "reply":
		// 构建应答帧
		if len(req.FlowData) != 4 {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "累积流量数据长度错误，需要4字节",
			})
			return
		}
		frameBytes, err = cj188.Build188Reply(req.MeterType, req.Addr, dataIDBytes, serial, req.FlowData, req.Status)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": fmt.Sprintf("构建应答帧失败: %v", err),
			})
			return
		}
		// 解析构建的帧以获取完整信息
		frame, err = cj188.Parser188(frameBytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": fmt.Sprintf("验证构建的帧失败: %v", err),
			})
			return
		}

	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "帧类型错误，支持: read, reply",
		})
		return
	}

	// 转换为DTO
	frameDTO := dto.ToFrameDTO(frame)
	hexStr := utils.HexTool.ToHexString(frameBytes)

	// 发布事件到eventbus
	eventData := map[string]interface{}{
		"type":    "build",
		"frame":   frameDTO,
		"hexData": hexStr,
	}
	eventDataBytes, _ := json.Marshal(eventData)
	eventbus.PublishAsync(eventbus.NewEvent("protocol.cj188.build", string(eventDataBytes)))

	c.JSON(http.StatusOK, dto.FrameResponse{
		Success:   true,
		Message:   "构建成功",
		HexData:   hexStr,
		Frame:     frameDTO,
		Timestamp: time.Now(),
	})
}

// SimulateCj188 模拟CJ188协议设备（从机）
func SimulateCj188(c *gin.Context) {
	var req dto.SimulateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("参数错误: %v", err),
		})
		return
	}

	// 设置默认值
	if len(req.FlowData) == 0 {
		// 默认累积流量：BCD码 [0x00, 0x02, 0x00, 0x00] = 20000
		req.FlowData = []byte{0x00, 0x02, 0x00, 0x00}
	}
	if req.BaudRate <= 0 {
		req.BaudRate = 2400
	}

	// 验证连接类型和参数
	switch req.ConnType {
	case "serial":
		if req.SerialPort == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "串口类型需要指定serialPort参数",
			})
			return
		}
	case "tcp_server", "tcp_client":
		if req.TCPAddress == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "TCP类型需要指定tcpAddress参数（格式: host:port）",
			})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "连接类型错误，支持: serial/tcp_server/tcp_client",
		})
		return
	}

	// 注册CJ188协议处理器（如果尚未注册）
	manager := simu.GetDefaultManager()
	_, err := manager.GetProtocolHandler("cj188")
	if err != nil {
		manager.RegisterProtocolHandler("cj188", simu.NewCJ188Handler())
	}

	// 转换FlowData为interface{}切片（用于JSON配置）
	flowDataInterface := make([]interface{}, len(req.FlowData))
	for i, b := range req.FlowData {
		flowDataInterface[i] = b
	}

	// 创建设备配置
	config := &simu.DeviceConfig{
		ProtocolType: "cj188",
		Config: map[string]interface{}{
			"meterType": req.MeterType,
			"addr":      req.Addr,
			"flowData":  flowDataInterface,
			"status":    req.Status,
		},
	}

	// 初始化设备状态（根据初始配置设置状态）
	// 注意：这里只是设置初始状态，实际状态会在设备运行过程中动态更新

	// 生成设备ID
	deviceID := fmt.Sprintf("%s_%s_%d", req.ConnType, req.Addr, time.Now().Unix())

	// 创建设备
	var device simu.Device

	switch req.ConnType {
	case "serial":
		device = simu.NewSerialDevice(config, req.SerialPort, req.BaudRate, manager)
	case "tcp_server":
		device = simu.NewTCPServerDevice(config, req.TCPAddress, manager)
	case "tcp_client":
		device = simu.NewTCPClientDevice(config, req.TCPAddress, req.Reconnect, manager)
	}

	// 设置事件回调，将设备事件发布到eventbus
	if baseDevice, ok := device.(interface {
		SetEventCallback(func(eventType string, data map[string]interface{}))
		GetState() *simu.DeviceState
	}); ok {
		baseDevice.SetEventCallback(func(eventType string, data map[string]interface{}) {
			// 发布事件到eventbus，主题为 device.{deviceID}.{eventType}
			topic := fmt.Sprintf("device.%s.%s", deviceID, eventType)
			eventData := map[string]interface{}{
				"deviceId":  deviceID,
				"eventType": eventType,
				"data":      data,
				"timestamp": time.Now().Format("2006-01-02 15:04:05"),
			}
			eventbus.PublishAsync(eventbus.NewEvent(topic, eventData))
		})

		// 初始化设备状态（根据初始配置）
		// CJ188协议：根据status字节解析初始状态
		state := baseDevice.GetState()
		if state != nil {
			// 解析状态字节，设置初始状态
			statusByte := byte(req.Status)
			// D0-D1: 阀门状态
			state.Set("valveStatus", int(statusByte&0x03))
			// D2: 电池状态
			state.Set("batteryStatus", (statusByte&0x04) != 0)
			// D6: IT05状态
			state.Set("it05Status", (statusByte&0x40) != 0)
			// D6-D7: 报警器状态
			state.Set("alarmStatus", int((statusByte>>6)&0x03))
			// 累积流量（从flowData BCD码转换）
			if len(req.FlowData) == 4 {
				flowBytes := make([]byte, 4)
				copy(flowBytes, req.FlowData)
				flowValue := utils.HexTool.BCDToUint32(flowBytes)
				state.Set("flowData", flowValue)
			}
		}
	}

	// 添加设备到管理器
	if err := manager.AddDevice(deviceID, device); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("添加设备失败: %v", err),
		})
		return
	}

	// 启动设备
	if err := device.Start(); err != nil {
		manager.RemoveDevice(deviceID)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("启动设备失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"message":  "模拟设备已启动",
		"deviceId": deviceID,
	})
}

// StopSimulateCj188 停止模拟设备
func StopSimulateCj188(c *gin.Context) {
	deviceID := c.Param("taskId")
	if deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "设备ID不能为空",
		})
		return
	}

	manager := simu.GetDefaultManager()
	device, exists := manager.GetDevice(deviceID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "设备不存在",
		})
		return
	}

	if !device.IsRunning() {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "设备未运行",
		})
		return
	}

	// 停止设备
	if err := device.Stop(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("停止设备失败: %v", err),
		})
		return
	}

	// 移除设备
	manager.RemoveDevice(deviceID)

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"message":  "设备已停止",
		"deviceId": deviceID,
	})
}

// DeviceEventsSSE 设备事件SSE流
func DeviceEventsSSE(c *gin.Context) {
	deviceID := c.Query("deviceId")
	if deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "设备ID不能为空",
		})
		return
	}

	// 设置SSE响应头
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "SSE不支持",
		})
		return
	}

	// 创建取消上下文
	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()

	// 订阅设备事件
	unsubscribe := eventbus.Subscribe(fmt.Sprintf("device.%s.*", deviceID), func(ctx context.Context, event eventbus.Event) error {
		// 将事件数据转换为JSON
		eventData, err := json.Marshal(event.Data())
		if err != nil {
			return err
		}

		// 发送SSE事件
		fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event.Topic(), string(eventData))
		flusher.Flush()
		return nil
	})
	defer unsubscribe()

	// 发送初始连接消息
	fmt.Fprintf(c.Writer, "event: connected\ndata: {\"message\":\"已连接到设备事件流\"}\n\n")
	flusher.Flush()

	// 保持连接，直到客户端断开
	<-ctx.Done()
}

// hexStringToBytes 将十六进制字符串转换为字节数组
func hexStringToBytes(hexStr string) ([]byte, error) {
	hexStr = strings.ReplaceAll(strings.ToUpper(hexStr), " ", "")
	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("十六进制字符串长度必须是偶数")
	}
	return utils.HexTool.ToBytes(hexStr), nil
}
