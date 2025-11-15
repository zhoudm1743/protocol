package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"protocol/app/dto"
	"protocol/pkg/eventbus"
	"protocol/pkg/simu"
	dlt645_2007 "protocol/protocol/dlt645-2007"
	"protocol/utils"

	"github.com/gin-gonic/gin"
)

// ParseDlt645_2007 解析DLT645-2007协议帧
func ParseDlt645_2007(c *gin.Context) {
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
	result := dlt645_2007.ParsePacket(bytes)
	if !result.Flag {
		c.JSON(http.StatusOK, dto.Dlt645_2007Response{
			Success:   false,
			Message:   "解析失败",
			Timestamp: time.Now(),
		})
		return
	}

	// 转换为DTO
	frameDTO := dto.ToDlt645_2007DTO(&result)
	hexStr := utils.HexTool.ToHexString(bytes)

	// 发布事件到eventbus
	eventData := map[string]interface{}{
		"type":    "parse",
		"frame":   frameDTO,
		"hexData": hexStr,
	}
	eventDataBytes, _ := json.Marshal(eventData)
	eventbus.PublishAsync(eventbus.NewEvent("protocol.dlt645-2007.parse", string(eventDataBytes)))

	c.JSON(http.StatusOK, dto.Dlt645_2007Response{
		Success:   true,
		Message:   "解析成功",
		HexData:   hexStr,
		Frame:     frameDTO,
		Timestamp: time.Now(),
	})
}

// BuildDlt645_2007 构建DLT645-2007协议帧
func BuildDlt645_2007(c *gin.Context) {
	var req dto.BuildDlt645_2007Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("参数错误: %v", err),
		})
		return
	}

	var frameBytes []byte

	// 根据帧类型构建
	switch req.FrameType {
	// 新版：读数据
	case "read_energy_positive":
		frameBytes = dlt645_2007.BuildReadDataPacket(req.Addr, dlt645_2007.DATA_ID_ENERGY_POSITIVE)
	case "read_energy_combined":
		frameBytes = dlt645_2007.BuildReadDataPacket(req.Addr, dlt645_2007.DATA_ID_ENERGY_COMBINED)
	case "read_energy_reverse":
		frameBytes = dlt645_2007.BuildReadDataPacket(req.Addr, dlt645_2007.DATA_ID_ENERGY_REVERSE)
	case "read_voltage_a":
		frameBytes = dlt645_2007.BuildReadDataPacket(req.Addr, dlt645_2007.DATA_ID_VOLTAGE_A)
	case "read_voltage_b":
		frameBytes = dlt645_2007.BuildReadDataPacket(req.Addr, dlt645_2007.DATA_ID_VOLTAGE_B)
	case "read_voltage_c":
		frameBytes = dlt645_2007.BuildReadDataPacket(req.Addr, dlt645_2007.DATA_ID_VOLTAGE_C)
	case "read_current_a":
		frameBytes = dlt645_2007.BuildReadDataPacket(req.Addr, dlt645_2007.DATA_ID_CURRENT_A)
	case "read_current_b":
		frameBytes = dlt645_2007.BuildReadDataPacket(req.Addr, dlt645_2007.DATA_ID_CURRENT_B)
	case "read_current_c":
		frameBytes = dlt645_2007.BuildReadDataPacket(req.Addr, dlt645_2007.DATA_ID_CURRENT_C)
	case "read_power_a":
		frameBytes = dlt645_2007.BuildReadDataPacket(req.Addr, dlt645_2007.DATA_ID_POWER_ACTIVE_A)
	case "read_power_total":
		frameBytes = dlt645_2007.BuildReadDataPacket(req.Addr, dlt645_2007.DATA_ID_POWER_ACTIVE_TOTAL)
	case "read_frequency":
		frameBytes = dlt645_2007.BuildReadDataPacket(req.Addr, dlt645_2007.DATA_ID_FREQUENCY)
	case "read_power_factor":
		frameBytes = dlt645_2007.BuildReadDataPacket(req.Addr, dlt645_2007.DATA_ID_POWER_FACTOR_TOTAL)
	case "read_comm_addr":
		frameBytes = dlt645_2007.ReadCommAddr(req.Addr)
	
	// 新版：写数据（需要dataId和writeData参数）
	case "write_data":
		if req.DataID == "" || req.WriteData == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "写数据需要提供数据标识和写入数据",
			})
			return
		}
		dataID, err := hexStringToBytes645(req.DataID)
		if err != nil || len(dataID) != 4 {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "数据标识格式错误，需要4字节十六进制",
			})
			return
		}
		writeData, err := hexStringToBytes645(req.WriteData)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "写入数据格式错误",
			})
			return
		}
		frameBytes = dlt645_2007.BuildWriteDataPacket(req.Addr, dataID, writeData)
	
	// 新版：控制命令
	case "control_on":
		frameBytes = dlt645_2007.TurnOnPacket(req.Addr)
	case "control_off":
		frameBytes = dlt645_2007.TurnOffPacket(req.Addr)
	
	// 旧版兼容
	case "read_0010":
		frameBytes = dlt645_2007.ReadPacket0010(req.Addr)
	case "read_0000":
		frameBytes = dlt645_2007.ReadPacket0000(req.Addr)
	case "read_0f22":
		frameBytes = dlt645_2007.ReadPacket0F22(req.Addr)
	case "turn_on":
		frameBytes = dlt645_2007.TurnOnPacket(req.Addr)
	case "turn_off":
		frameBytes = dlt645_2007.TurnOffPacket(req.Addr)
	
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "帧类型错误",
		})
		return
	}

	// 解析构建的帧以获取完整信息
	result := dlt645_2007.ParsePacket(frameBytes)
	frameDTO := dto.ToDlt645_2007DTO(&result)
	hexStr := utils.HexTool.ToHexString(frameBytes)

	// 发布事件到eventbus
	eventData := map[string]interface{}{
		"type":    "build",
		"frame":   frameDTO,
		"hexData": hexStr,
	}
	eventDataBytes, _ := json.Marshal(eventData)
	eventbus.PublishAsync(eventbus.NewEvent("protocol.dlt645-2007.build", string(eventDataBytes)))

	c.JSON(http.StatusOK, dto.Dlt645_2007Response{
		Success:   true,
		Message:   "构建成功",
		HexData:   hexStr,
		Frame:     frameDTO,
		Timestamp: time.Now(),
	})
}

// SimulateDlt645_2007 模拟DLT645-2007协议设备
func SimulateDlt645_2007(c *gin.Context) {
	var req dto.SimulateDlt645_2007Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": fmt.Sprintf("参数错误: %v", err),
		})
		return
	}

	// 设置默认值
	if req.MeterData == 0 {
		req.MeterData = 12345.67 // 默认电能数据
	}
	if req.Ia == 0 {
		req.Ia = 10.5 // 默认A相电流
	}
	if req.Ib == 0 {
		req.Ib = 10.3 // 默认B相电流
	}
	if req.Ic == 0 {
		req.Ic = 10.8 // 默认C相电流
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

	// 注册DLT645-2007协议处理器
	manager := simu.GetDefaultManager()
	_, err := manager.GetProtocolHandler("dlt645-2007")
	if err != nil {
		manager.RegisterProtocolHandler("dlt645-2007", simu.NewDLT645_2007Handler())
	}

	// 创建设备配置
	config := &simu.DeviceConfig{
		ProtocolType: "dlt645-2007",
		Config: map[string]interface{}{
			"addr":       req.Addr,
			"meterData":  req.MeterData,
			"ia":         req.Ia,
			"ib":         req.Ib,
			"ic":         req.Ic,
			"relayStatus": true, // 默认继电器合闸
		},
	}

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
		
		// 启动状态更新推送（每3秒推送一次）
		if statusUpdater, ok := device.(interface{ StartStatusUpdate(time.Duration) }); ok {
			statusUpdater.StartStatusUpdate(3 * time.Second)
		}

		// 初始化设备状态
		state := baseDevice.GetState()
		if state != nil {
			state.Set("meterData", req.MeterData)
			state.Set("ia", req.Ia)
			state.Set("ib", req.Ib)
			state.Set("ic", req.Ic)
			state.Set("relayStatus", true)
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

// StopSimulateDlt645_2007 停止模拟设备
func StopSimulateDlt645_2007(c *gin.Context) {
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

	// 停止状态推送
	if statusUpdater, ok := device.(interface{ StopStatusUpdate() }); ok {
		statusUpdater.StopStatusUpdate()
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

// DeviceEventsDlt645SSE 设备事件SSE流
func DeviceEventsDlt645SSE(c *gin.Context) {
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
		eventData, err := json.Marshal(event.Data())
		if err != nil {
			return err
		}

		fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event.Topic(), string(eventData))
		flusher.Flush()
		return nil
	})
	defer unsubscribe()

	// 发送初始连接消息
	fmt.Fprintf(c.Writer, "event: connected\ndata: {\"message\":\"已连接到设备事件流\"}\n\n")
	flusher.Flush()

	// 保持连接
	<-ctx.Done()
}

// GetDeviceStatusDLT645 获取设备状态
func GetDeviceStatusDLT645(c *gin.Context) {
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

	// 获取设备状态
	state := device.GetState()
	stateData := state.GetAll()

	// 获取统计信息
	stats := device.GetStatistics()
	statsSnapshot := stats.GetSnapshot()

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"deviceId":   deviceID,
		"isRunning":  device.IsRunning(),
		"state":      stateData,
		"statistics": statsSnapshot,
		"protocol":   device.GetConfig().ProtocolType,
		"timestamp":  time.Now().Format("2006-01-02 15:04:05"),
	})
}

// GetDeviceStatisticsDLT645 获取设备统计信息
func GetDeviceStatisticsDLT645(c *gin.Context) {
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

	stats := device.GetStatistics()
	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"deviceId":   deviceID,
		"statistics": stats.GetSnapshot(),
	})
}

// hexStringToBytes645 将十六进制字符串转换为字节数组
func hexStringToBytes645(hexStr string) ([]byte, error) {
	hexStr = strings.ReplaceAll(strings.ToUpper(hexStr), " ", "")
	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("十六进制字符串长度必须是偶数")
	}
	return utils.HexTool.ToBytes(hexStr), nil
}
