package simu

import (
	"bytes"
	"fmt"

	"protocol/pkg/logger"
	dlt645_2007 "protocol/protocol/dlt645-2007"
	"protocol/utils"
)

// buildReadDataReply 构建读数据应答帧
func (h *DLT645_2007Handler) buildReadDataReply(req *dlt645_2007.DataResult, addr string, config *DeviceConfig) ([]byte, error) {
	if req.DataLen < 4 {
		return nil, fmt.Errorf("数据标识长度不足")
	}

	// 解析数据标识（已经解码过-0x33）
	dataIDBytes := utils.HexTool.ToBytes(req.DataID)
	if len(dataIDBytes) != 4 {
		return nil, fmt.Errorf("数据标识格式错误")
	}

	// 获取状态（从config中获取）
	state := NewDeviceState()
	h.initDefaultValues(config, state)

	di3 := dataIDBytes[0]
	di2 := dataIDBytes[1]
	di1 := dataIDBytes[2]

	var dataBytes []byte

	switch di3 {
	case 0x00: // 电能量数据
		// 获取电能数据
		meterData, _ := state.Get("meterData")
		val := 0.0
		if v, ok := meterData.(float64); ok {
			val = v
		}
		dataBytes = dlt645_2007.WriteBCDValue(val)
		logger.Debugf("DLT645-2007: 读取电能数据 %.2f kWh", val)

	case 0x02: // 变量数据
		switch di2 {
		case 0x01: // 电压
			switch di1 {
			case 0x01: // A相电压
				va, _ := state.Get("va")
				if v, ok := va.(float64); ok {
					dataBytes = encodeVoltage(v)
					logger.Debugf("DLT645-2007: 读取A相电压 %.1f V", v)
				}
			case 0x02: // B相电压
				vb, _ := state.Get("vb")
				if v, ok := vb.(float64); ok {
					dataBytes = encodeVoltage(v)
					logger.Debugf("DLT645-2007: 读取B相电压 %.1f V", v)
				}
			case 0x03: // C相电压
				vc, _ := state.Get("vc")
				if v, ok := vc.(float64); ok {
					dataBytes = encodeVoltage(v)
					logger.Debugf("DLT645-2007: 读取C相电压 %.1f V", v)
				}
			}

		case 0x02: // 电流
			switch di1 {
			case 0x01: // A相电流
				ia, _ := state.Get("ia")
				if v, ok := ia.(float64); ok {
					dataBytes = encodeCurrent(v)
					logger.Debugf("DLT645-2007: 读取A相电流 %.3f A", v)
				}
			case 0x02: // B相电流
				ib, _ := state.Get("ib")
				if v, ok := ib.(float64); ok {
					dataBytes = encodeCurrent(v)
					logger.Debugf("DLT645-2007: 读取B相电流 %.3f A", v)
				}
			case 0x03: // C相电流
				ic, _ := state.Get("ic")
				if v, ok := ic.(float64); ok {
					dataBytes = encodeCurrent(v)
					logger.Debugf("DLT645-2007: 读取C相电流 %.3f A", v)
				}
			}

		case 0x03: // 有功功率
			switch di1 {
			case 0x00: // 总有功功率
				pa, _ := state.Get("pa")
				pb, _ := state.Get("pb")
				pc, _ := state.Get("pc")
				total := 0.0
				if v, ok := pa.(float64); ok {
					total += v
				}
				if v, ok := pb.(float64); ok {
					total += v
				}
				if v, ok := pc.(float64); ok {
					total += v
				}
				dataBytes = encodePower(total)
				logger.Debugf("DLT645-2007: 读取总有功功率 %.4f kW", total)

			case 0x01: // A相有功功率
				pa, _ := state.Get("pa")
				if v, ok := pa.(float64); ok {
					dataBytes = encodePower(v)
					logger.Debugf("DLT645-2007: 读取A相有功功率 %.4f kW", v)
				}
			case 0x02: // B相有功功率
				pb, _ := state.Get("pb")
				if v, ok := pb.(float64); ok {
					dataBytes = encodePower(v)
					logger.Debugf("DLT645-2007: 读取B相有功功率 %.4f kW", v)
				}
			case 0x03: // C相有功功率
				pc, _ := state.Get("pc")
				if v, ok := pc.(float64); ok {
					dataBytes = encodePower(v)
					logger.Debugf("DLT645-2007: 读取C相有功功率 %.4f kW", v)
				}
			}

		case 0x06: // 功率因数
			pf, _ := state.Get("powerFactor")
			if v, ok := pf.(float64); ok {
				dataBytes = encodePowerFactor(v)
				logger.Debugf("DLT645-2007: 读取功率因数 %.3f", v)
			}

		case 0x80: // 频率
			freq, _ := state.Get("frequency")
			if v, ok := freq.(float64); ok {
				dataBytes = encodeFrequency(v)
				logger.Debugf("DLT645-2007: 读取频率 %.2f Hz", v)
			}
		}

	case 0x04: // 参变量
		// 读取通信地址或表号
		if bytes.Equal(dataIDBytes, dlt645_2007.DATA_ID_COMM_ADDR) {
			// 返回通信地址
			dataBytes = utils.HexTool.BytesReverse(utils.HexTool.ToBytes(addr))
			logger.Debugf("DLT645-2007: 读取通信地址 %s", addr)
		}
	}

	if len(dataBytes) == 0 {
		return nil, fmt.Errorf("不支持的数据标识: %s", req.DataID)
	}

	// 构建应答帧
	return buildResponseFrame(addr, 0x91, dataIDBytes, dataBytes), nil
}

// buildReadAddressReply 构建读通信地址应答帧
func (h *DLT645_2007Handler) buildReadAddressReply(addr string) ([]byte, error) {
	// DLT645-2007 读通信地址应答
	// 控制码: 0x93
	// 数据: 6字节地址
	addrBytes := utils.HexTool.BytesReverse(utils.HexTool.ToBytes(addr))
	
	logger.Debugf("DLT645-2007: 读取通信地址应答 %s", addr)
	
	return buildResponseFrame(addr, 0x93, nil, addrBytes), nil
}

// buildWriteDataReply 构建写数据应答帧
func (h *DLT645_2007Handler) buildWriteDataReply(req *dlt645_2007.DataResult, addr string) ([]byte, error) {
	// 写数据成功应答
	// 控制码: 0x94
	logger.Debugf("DLT645-2007: 写数据应答")
	
	return buildResponseFrame(addr, 0x94, nil, nil), nil
}

// buildControlReply 构建控制命令应答帧
func (h *DLT645_2007Handler) buildControlReply(req *dlt645_2007.DataResult, addr string, config *DeviceConfig) ([]byte, error) {
	// 控制命令应答
	// 成功: 0x9C, 失败: 0xDC
	
	// 检查继电器状态
	relayStatus := true
	if val, ok := config.Config["relayStatus"].(bool); ok {
		relayStatus = val
	}
	
	controlCode := byte(0x9C) // 默认成功
	if !relayStatus {
		// 根据实际情况可能失败
		// 这里简化处理，假设总是成功
	}
	
	logger.Debugf("DLT645-2007: 控制命令应答 (0x%02X)", controlCode)
	
	return buildResponseFrame(addr, controlCode, nil, nil), nil
}

// buildErrorReply 构建异常应答帧
func (h *DLT645_2007Handler) buildErrorReply(addr string, controlCode byte, errorCode byte) []byte {
	// 异常应答帧
	// 控制码最高位为1，第6位为1表示异常
	replyCode := (controlCode | 0x80 | 0x40)
	
	// 数据域包含错误码
	errorData := []byte{errorCode}
	
	logger.Debugf("DLT645-2007: 异常应答 控制码=0x%02X, 错误码=0x%02X", replyCode, errorCode)
	
	return buildResponseFrame(addr, replyCode, nil, errorData)
}

// ==================== 数据编码辅助函数 ====================

// buildResponseFrame 构建应答帧
func buildResponseFrame(addr string, controlCode byte, dataID []byte, data []byte) []byte {
	buf := bytes.Buffer{}
	
	// 起始符
	buf.WriteByte(0x68)
	
	// 地址域（6字节，低字节在前）
	addrBytes := utils.HexTool.BytesReverse(utils.HexTool.ToBytes(addr))
	buf.Write(addrBytes)
	
	// 起始符
	buf.WriteByte(0x68)
	
	// 控制码
	buf.WriteByte(controlCode)
	
	// 数据长度
	dataLen := len(dataID) + len(data)
	buf.WriteByte(byte(dataLen))
	
	// 数据域（需要加0x33编码）
	if len(dataID) > 0 {
		for _, b := range dataID {
			buf.WriteByte(b + 0x33)
		}
	}
	if len(data) > 0 {
		for _, b := range data {
			buf.WriteByte(b + 0x33)
		}
	}
	
	// 校验和（从第一个68开始到校验码前的所有字节相加，取低8位）
	checksum := byte(0)
	frameBytes := buf.Bytes()
	for _, b := range frameBytes {
		checksum += b
	}
	buf.WriteByte(checksum)
	
	// 结束符
	buf.WriteByte(0x16)
	
	return buf.Bytes()
}

// encodeVoltage 编码电压数据（2字节，单位0.1V）
func encodeVoltage(voltage float64) []byte {
	// 转换为整数（单位0.1V）
	intVal := int(voltage * 10)
	// 转换为BCD码
	bcd := fmt.Sprintf("%04d", intVal)
	data := utils.HexTool.ToBytes(bcd)
	// 低字节在前
	return utils.HexTool.BytesReverse(data)
}

// encodeCurrent 编码电流数据（3字节，单位0.001A）
func encodeCurrent(current float64) []byte {
	// 转换为整数（单位0.001A）
	intVal := int(current * 1000)
	// 转换为BCD码
	bcd := fmt.Sprintf("%06d", intVal)
	data := utils.HexTool.ToBytes(bcd)
	// 低字节在前
	return utils.HexTool.BytesReverse(data)
}

// encodePower 编码功率数据（3字节，单位0.0001kW）
func encodePower(power float64) []byte {
	// 转换为整数（单位0.0001kW）
	intVal := int(power * 10000)
	// 转换为BCD码
	bcd := fmt.Sprintf("%06d", intVal)
	data := utils.HexTool.ToBytes(bcd)
	// 低字节在前
	return utils.HexTool.BytesReverse(data)
}

// encodePowerFactor 编码功率因数（2字节，单位0.001）
func encodePowerFactor(pf float64) []byte {
	// 转换为整数（单位0.001）
	intVal := int(pf * 1000)
	// 转换为BCD码
	bcd := fmt.Sprintf("%04d", intVal)
	data := utils.HexTool.ToBytes(bcd)
	// 低字节在前
	return utils.HexTool.BytesReverse(data)
}

// encodeFrequency 编码频率数据（2字节，单位0.01Hz）
func encodeFrequency(freq float64) []byte {
	// 转换为整数（单位0.01Hz）
	intVal := int(freq * 100)
	// 转换为BCD码
	bcd := fmt.Sprintf("%04d", intVal)
	data := utils.HexTool.ToBytes(bcd)
	// 低字节在前
	return utils.HexTool.BytesReverse(data)
}
