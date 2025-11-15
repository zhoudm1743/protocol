package simu

import (
	"fmt"

	"protocol/pkg/logger"
	dlt645_2007 "protocol/protocol/dlt645-2007"
)

// DLT645_2007Handler DLT645-2007协议处理器
type DLT645_2007Handler struct{}

// NewDLT645_2007Handler 创建DLT645-2007协议处理器
func NewDLT645_2007Handler() *DLT645_2007Handler {
	return &DLT645_2007Handler{}
}

// ParseRequest 解析请求帧
func (h *DLT645_2007Handler) ParseRequest(data []byte) (interface{}, error) {
	result := dlt645_2007.ParsePacket(data)
	if !result.Flag {
		return nil, fmt.Errorf("解析DLT645-2007请求帧失败")
	}
	return &result, nil
}

// BuildReply 构建应答帧
func (h *DLT645_2007Handler) BuildReply(request interface{}, config *DeviceConfig) ([]byte, error) {
	req, ok := request.(*dlt645_2007.DataResult)
	if !ok {
		return nil, fmt.Errorf("请求类型错误，期望*DataResult")
	}

	// 从配置中获取设备地址
	addrValue, exists := config.Config["addr"]
	if !exists {
		return nil, fmt.Errorf("配置中缺少addr")
	}
	addr, ok := addrValue.(string)
	if !ok {
		return nil, fmt.Errorf("addr类型错误")
	}

	// 只处理请求帧
	if !req.IsRequest {
		return nil, fmt.Errorf("不是请求帧")
	}

	// 根据控制码处理不同类型的请求
	switch req.ControlCode {
	case 0x11: // 读数据
		return h.buildReadDataReply(req, addr, config)
	case 0x13: // 读通信地址
		return h.buildReadAddressReply(addr)
	case 0x14: // 写数据
		return h.buildWriteDataReply(req, addr)
	case 0x1C: // 控制命令（拉合闸）
		return h.buildControlReply(req, addr, config)
	default:
		// 不支持的命令，返回异常应答
		return h.buildErrorReply(addr, req.ControlCode, 0x01), nil // 0x01: 无效命令
	}
}

// ValidateAddress 验证地址是否匹配
func (h *DLT645_2007Handler) ValidateAddress(request interface{}, config *DeviceConfig) bool {
	result, ok := request.(*dlt645_2007.DataResult)
	if !ok {
		return false
	}

	// 从配置中获取设备地址
	addrValue, exists := config.Config["addr"]
	if !exists {
		return false
	}

	configAddr, ok := addrValue.(string)
	if !ok {
		return false
	}

	reqAddr := result.DeviceCode
	
	// 检查是否为广播地址（999999999999或FFFFFFFFFFFF）
	if reqAddr == "999999999999" || reqAddr == "FFFFFFFFFFFF" {
		return true
	}
	
	// 检查是否使用通配符地址（AA表示通配符）
	// DLT645-2007支持缩位寻址，高位可用AA作为通配符
	for i := 0; i < len(reqAddr); i += 2 {
		if i+1 < len(reqAddr) {
			reqByte := reqAddr[i:i+2]
			if reqByte == "AA" {
				// 遇到通配符，匹配成功
				continue
			}
			// 比较对应位置
			if i+1 < len(configAddr) {
				cfgByte := configAddr[i:i+2]
				if reqByte != cfgByte {
					return false
				}
			}
		}
	}
	
	return true
}

// BuildReport 构建主动上报帧（DLT645-2007不支持主动上报）
func (h *DLT645_2007Handler) BuildReport(config *DeviceConfig, reportType string, data map[string]interface{}) ([]byte, error) {
	return nil, fmt.Errorf("DLT645-2007协议不支持主动上报")
}

// GetAddresses 获取设备地址
func (h *DLT645_2007Handler) GetAddresses(config *DeviceConfig) (primaryAddr string, secondaryAddr string) {
	addr, ok := config.Config["addr"].(string)
	if ok {
		return addr, ""
	}
	return "", ""
}

// SupportActiveReport 是否支持主动上报
func (h *DLT645_2007Handler) SupportActiveReport() bool {
	return false
}

// HandleCommand 处理控制指令
func (h *DLT645_2007Handler) HandleCommand(request interface{}, config *DeviceConfig, state *DeviceState) (success bool, stateChanges map[string]interface{}, reply []byte, err error) {
	result, ok := request.(*dlt645_2007.DataResult)
	if !ok {
		return false, nil, nil, nil
	}

	stateChanges = make(map[string]interface{})
	
	// 初始化默认值
	h.initDefaultValues(config, state)

	// 只有写数据和控制命令才会改变状态
	if result.ControlCode == 0x14 { // 写数据
		// 写数据操作（暂不实现具体逻辑）
		logger.Debugf("DLT645-2007: 写数据请求，数据标识=%s", result.DataID)
		
	} else if result.ControlCode == 0x1C { // 控制命令（拉合闸）
		logger.Debugf("DLT645-2007: 控制命令请求")
		
		// 解析控制数据，判断是合闸还是跳闸
		// DLT645-2007控制命令数据标识：1C 后跟操作码
		// 具体需要解析DataID来判断
		if len(result.DataID) >= 8 {
			// 简化处理：假设配置中已经包含relayStatus信息
			if relayValue, ok := config.Config["relayStatus"]; ok {
				if relay, ok := relayValue.(bool); ok {
					state.Set("relayStatus", relay)
					stateChanges["relayStatus"] = relay
					logger.Debugf("DLT645-2007: 继电器状态变更为 %v", relay)
				}
			}
		}
	}

	return true, stateChanges, nil, nil
}

// GetCommandInfo 获取指令信息
func (h *DLT645_2007Handler) GetCommandInfo(request interface{}) (commandType string, commandDesc string) {
	result, ok := request.(*dlt645_2007.DataResult)
	if !ok {
		return "unknown", "未知指令"
	}

	// 根据控制码和帧类型描述
	if result.FrameType != "" {
		return fmt.Sprintf("cmd_0x%02X", result.ControlCode), result.FrameType
	}
	
	// 对于数据标识，添加详细描述
	if result.DataIDDesc != "" {
		return fmt.Sprintf("read_%s", result.DataID), result.DataIDDesc
	}

	switch result.ControlCode {
	case 0x11:
		return "read_data", "读取数据"
	case 0x13:
		return "read_addr", "读取通信地址"
	case 0x14:
		return "write_data", "写入数据"
	case 0x1C:
		return "control", "控制命令"
	default:
		return "unknown", "未知指令"
	}
}

// ==================== 辅助函数 ====================

// initDefaultValues 初始化默认值
func (h *DLT645_2007Handler) initDefaultValues(config *DeviceConfig, state *DeviceState) {
	// 初始化电能数据
	if _, exists := state.Get("meterData"); !exists {
		if val, ok := config.Config["meterData"].(float64); ok {
			state.Set("meterData", val)
		} else {
			state.Set("meterData", 0.0)
		}
	}
	
	// 初始化电流数据
	if _, exists := state.Get("ia"); !exists {
		if val, ok := config.Config["ia"].(float64); ok {
			state.Set("ia", val)
		} else {
			state.Set("ia", 0.0)
		}
	}
	if _, exists := state.Get("ib"); !exists {
		if val, ok := config.Config["ib"].(float64); ok {
			state.Set("ib", val)
		} else {
			state.Set("ib", 0.0)
		}
	}
	if _, exists := state.Get("ic"); !exists {
		if val, ok := config.Config["ic"].(float64); ok {
			state.Set("ic", val)
		} else {
			state.Set("ic", 0.0)
		}
	}
	
	// 初始化电压数据（默认220V）
	if _, exists := state.Get("va"); !exists {
		state.Set("va", 220.0)
	}
	if _, exists := state.Get("vb"); !exists {
		state.Set("vb", 220.0)
	}
	if _, exists := state.Get("vc"); !exists {
		state.Set("vc", 220.0)
	}
	
	// 初始化功率数据
	if _, exists := state.Get("pa"); !exists {
		state.Set("pa", 0.0)
	}
	if _, exists := state.Get("pb"); !exists {
		state.Set("pb", 0.0)
	}
	if _, exists := state.Get("pc"); !exists {
		state.Set("pc", 0.0)
	}
	
	// 初始化频率（默认50Hz）
	if _, exists := state.Get("frequency"); !exists {
		state.Set("frequency", 50.0)
	}
	
	// 初始化功率因数（默认0.9）
	if _, exists := state.Get("powerFactor"); !exists {
		state.Set("powerFactor", 0.9)
	}
	
	// 初始化继电器状态（默认合闸）
	if _, exists := state.Get("relayStatus"); !exists {
		if val, ok := config.Config["relayStatus"].(bool); ok {
			state.Set("relayStatus", val)
		} else {
			state.Set("relayStatus", true)
		}
	}
}
