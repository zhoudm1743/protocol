package simu

import (
	"fmt"

	"protocol/pkg/logger"
	"protocol/protocol/cj188"
	"protocol/utils"
)

// CJ188Handler CJ188协议处理器
type CJ188Handler struct{}

// NewCJ188Handler 创建CJ188协议处理器
func NewCJ188Handler() *CJ188Handler {
	return &CJ188Handler{}
}

// ParseRequest 解析请求帧
func (h *CJ188Handler) ParseRequest(data []byte) (interface{}, error) {
	frame, err := cj188.Parser188(data)
	if err != nil {
		return nil, fmt.Errorf("解析CJ188请求帧失败: %v", err)
	}
	return frame, nil
}

// BuildReply 构建应答帧
func (h *CJ188Handler) BuildReply(request interface{}, config *DeviceConfig) ([]byte, error) {
	frame, ok := request.(*cj188.Cj188Frame)
	if !ok {
		return nil, fmt.Errorf("请求类型错误，期望*Cj188Frame")
	}

	// 从配置中获取参数（支持多种类型转换）
	meterTypeValue, exists := config.Config["meterType"]
	if !exists {
		return nil, fmt.Errorf("配置中缺少meterType")
	}

	var meterType byte
	switch v := meterTypeValue.(type) {
	case byte:
		meterType = v
	case int:
		meterType = byte(v)
	case int32:
		meterType = byte(v)
	case int64:
		meterType = byte(v)
	case float64:
		meterType = byte(v)
	case float32:
		meterType = byte(v)
	default:
		return nil, fmt.Errorf("meterType类型错误: %T", v)
	}

	addr, ok := config.Config["addr"].(string)
	if !ok {
		return nil, fmt.Errorf("配置中缺少addr")
	}

	flowData, ok := config.Config["flowData"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("配置中缺少flowData")
	}

	// 转换flowData为[]byte（支持多种数字类型）
	flowDataBytes := make([]byte, len(flowData))
	for i, v := range flowData {
		var b byte
		switch val := v.(type) {
		case byte:
			b = val
		case int:
			b = byte(val)
		case int32:
			b = byte(val)
		case int64:
			b = byte(val)
		case float64:
			b = byte(val)
		case float32:
			b = byte(val)
		default:
			return nil, fmt.Errorf("flowData格式错误: 索引%d的类型为%T，期望数字类型", i, val)
		}
		flowDataBytes[i] = b
	}

	// 从设备状态获取状态字节（通过配置传递）
	var statusByte byte
	if state, ok := config.Config["_deviceState"].(*DeviceState); ok && state != nil {
		statusByte = state.GetStatusByte()
	} else {
		// 如果状态不存在，使用配置中的状态
		if status, ok := config.Config["status"].(float64); ok {
			statusByte = byte(status)
		}
	}

	// 从查询帧中获取数据标识（设备作为从机，应该使用查询帧中的数据标识）
	dataIDBytes := frame.DataID
	if len(dataIDBytes) != 2 {
		return nil, fmt.Errorf("查询帧中数据标识格式错误")
	}

	// 构建应答帧
	replyFrame, err := cj188.Build188Reply(
		meterType,
		addr,
		dataIDBytes,
		frame.Serial,
		flowDataBytes,
		statusByte,
	)
	if err != nil {
		return nil, fmt.Errorf("构建CJ188应答帧失败: %v", err)
	}

	return replyFrame, nil
}

// ValidateAddress 验证地址是否匹配（CJ188只有单地址）
func (h *CJ188Handler) ValidateAddress(request interface{}, config *DeviceConfig) bool {
	frame, ok := request.(*cj188.Cj188Frame)
	if !ok {
		return false
	}

	addr, ok := config.Config["addr"].(string)
	if !ok {
		return false
	}

	// 直接比较地址字符串（严格匹配）
	requestAddr := frame.Addr
	configAddr := addr

	// 严格比较，必须完全匹配
	match := requestAddr == configAddr

	// 如果地址不匹配，记录日志（用于调试）
	if !match {
		logger.Debugf("[CJ188地址验证] 地址不匹配: 请求地址=%s, 配置地址=%s", requestAddr, configAddr)
	}

	return match
}

// BuildReport 构建主动上报帧（CJ188不支持主动上报）
func (h *CJ188Handler) BuildReport(config *DeviceConfig, reportType string, data map[string]interface{}) ([]byte, error) {
	return nil, fmt.Errorf("CJ188协议不支持主动上报")
}

// GetAddresses 获取设备地址（CJ188只有主地址）
func (h *CJ188Handler) GetAddresses(config *DeviceConfig) (primaryAddr string, secondaryAddr string) {
	addr, ok := config.Config["addr"].(string)
	if ok {
		return addr, ""
	}
	return "", ""
}

// SupportActiveReport 是否支持主动上报
func (h *CJ188Handler) SupportActiveReport() bool {
	return false
}

// HandleCommand 处理控制指令（CJ188协议支持的控制指令）
func (h *CJ188Handler) HandleCommand(request interface{}, config *DeviceConfig, state *DeviceState) (success bool, stateChanges map[string]interface{}, reply []byte, err error) {
	frame, ok := request.(*cj188.Cj188Frame)
	if !ok {
		return false, nil, nil, nil
	}

	// 获取配置参数
	meterTypeValue, exists := config.Config["meterType"]
	if !exists {
		return false, nil, nil, fmt.Errorf("配置中缺少meterType")
	}

	var meterType byte
	switch v := meterTypeValue.(type) {
	case byte:
		meterType = v
	case int:
		meterType = byte(v)
	case float64:
		meterType = byte(v)
	default:
		meterType = byte(16) // 默认水表
	}

	addr, ok := config.Config["addr"].(string)
	if !ok {
		return false, nil, nil, fmt.Errorf("配置中缺少addr")
	}

	// 处理控制指令
	switch frame.Control {
	case cj188.CTRL_CLOSE_VALVE:
		// 关阀指令
		state.Set("valveStatus", 1) // 1-关阀

		// 构建应答帧（控制指令应答：控制码+0x80）
		replyFrame, err := h.buildControlReply(meterType, addr, frame.Control, frame.Serial)
		if err != nil {
			return false, nil, nil, err
		}

		return true, map[string]interface{}{
			"valveStatus": 1,
		}, replyFrame, nil
	case cj188.CTRL_OPEN_VALVE:
		// 开阀指令
		state.Set("valveStatus", 0) // 0-开阀

		// 构建应答帧
		replyFrame, err := h.buildControlReply(meterType, addr, frame.Control, frame.Serial)
		if err != nil {
			return false, nil, nil, err
		}

		return true, map[string]interface{}{
			"valveStatus": 0,
		}, replyFrame, nil
	case cj188.CTRL_SET_PARAM:
		// 设置参数指令（可以根据数据域内容设置不同参数）
		// 这里简化处理，实际应该根据数据域内容解析参数

		// 构建应答帧
		replyFrame, err := h.buildControlReply(meterType, addr, frame.Control, frame.Serial)
		if err != nil {
			return false, nil, nil, err
		}

		return true, nil, replyFrame, nil
	default:
		// 不是控制指令，返回false让系统按查询指令处理
		return false, nil, nil, nil
	}
}

// buildControlReply 构建控制指令应答帧
// 实际设备应答格式：68 10 地址(7) A5 05 A0 序列号 00 00 FF 校验和 16
// 数据域：A0（操作码）+ 序列号(1) + 00 00（保留）+ FF（执行结果）
func (h *CJ188Handler) buildControlReply(meterType byte, addr string, controlCode byte, serial byte) ([]byte, error) {
	// 将地址转换为BCD码
	addrBytes, err := utils.HexTool.DecimalToBCD(addr, 7)
	if err != nil {
		return nil, fmt.Errorf("地址转换失败: %v", err)
	}

	// 根据控制码确定应答控制码和操作码
	var replyControl byte
	var operationCode byte

	switch controlCode {
	case cj188.CTRL_CLOSE_VALVE:
		// 关阀应答：控制码0xA5，操作码0xA0
		replyControl = 0xA5
		operationCode = 0xA0
	case cj188.CTRL_OPEN_VALVE:
		// 开阀应答：控制码0xA6，操作码0xA1（推测）
		replyControl = 0xA6
		operationCode = 0xA1
	case cj188.CTRL_SET_PARAM:
		// 设置参数应答：控制码0xA7，操作码0xA2（推测）
		replyControl = 0xA7
		operationCode = 0xA2
	default:
		// 默认：控制码+0x80
		replyControl = controlCode + 0x80
		operationCode = 0xA0
	}

	// 构建数据域（5字节）：操作码(1) + 序列号(1) + 保留(2) + 执行结果(1)
	dataField := make([]byte, 5)
	dataField[0] = operationCode // 操作码
	dataField[1] = serial        // 序列号
	dataField[2] = 0x00          // 保留
	dataField[3] = 0x00          // 保留
	dataField[4] = 0xFF          // 执行结果（FF表示成功）

	// 构建应答帧
	frame := make([]byte, 0, 20)
	frame = append(frame, cj188.FRAME_START)    // 帧起始符
	frame = append(frame, meterType)            // 表计类型
	frame = append(frame, addrBytes...)         // 地址（7字节）
	frame = append(frame, replyControl)         // 应答控制码
	frame = append(frame, byte(len(dataField))) // 数据域长度（5字节）
	frame = append(frame, dataField...)         // 数据域

	// 计算校验和
	checksum := utils.HexTool.CheckSum(frame)
	frame = append(frame, checksum)        // 校验和
	frame = append(frame, cj188.FRAME_END) // 帧结束符

	return frame, nil
}

// GetCommandInfo 获取指令信息（用于显示）
func (h *CJ188Handler) GetCommandInfo(request interface{}) (commandType string, commandDesc string) {
	frame, ok := request.(*cj188.Cj188Frame)
	if !ok {
		return "unknown", "未知指令"
	}

	// 根据控制码判断指令类型
	switch frame.Control {
	case cj188.CTRL_READ:
		// 根据数据标识判断具体查询类型
		if len(frame.DataID) == 2 {
			dataIDStr := fmt.Sprintf("%02X%02X", frame.DataID[0], frame.DataID[1])
			return "read", fmt.Sprintf("读数据 (数据标识: %s)", dataIDStr)
		}
		return "read", "读数据"
	case cj188.CTRL_REPLY:
		return "reply", "数据应答"
	case cj188.CTRL_CLOSE_VALVE:
		return "control", "关阀指令"
	case cj188.CTRL_OPEN_VALVE:
		return "control", "开阀指令"
	case cj188.CTRL_SET_PARAM:
		return "control", "设置参数指令"
	case cj188.CTRL_REPLY_CLOSE:
		return "reply", "关阀应答"
	case cj188.CTRL_REPLY_OPEN:
		return "reply", "开阀应答"
	case cj188.CTRL_REPLY_SET_PARAM:
		return "reply", "设置参数应答"
	default:
		return "unknown", fmt.Sprintf("未知控制码 (0x%02X)", frame.Control)
	}
}
