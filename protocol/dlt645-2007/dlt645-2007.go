package dlt645_2007

import (
	"bytes"
	"fmt"
	lg "protocol/pkg/logger"
	"protocol/utils"
	"strconv"
	"time"
)

type DataResult struct {
	Data         float64 // 电能数据
	TurnResult   bool    // 拉合闸结果
	Flag         bool    // 解包成功标志 false为失败
	DeviceCode   string  // 设备地址
	DataType     int     // 0=电能 1=拉合闸 2=电流 3=请求帧 4=电压 5=功率 6=频率
	Ia           float64 // A相电流
	Ib           float64 // B相电流
	Ic           float64 // C相电流
	Va           float64 // A相电压
	Vb           float64 // B相电压
	Vc           float64 // C相电压
	Pa           float64 // A相有功功率
	Pb           float64 // B相有功功率
	Pc           float64 // C相有功功率
	Frequency    float64 // 频率
	PowerFactor  float64 // 功率因数
	ControlCode  byte    // 控制码
	DataLen      int     // 数据长度
	DataID       string  // 数据标识（十六进制字符串）
	DataIDDesc   string  // 数据标识描述
	IsRequest    bool    // 是否为请求帧
	IsResponse   bool    // 是否为应答帧
	FrameType    string  // 帧类型描述
}

// ==================== 数据标识常量定义 ====================
// DLT645-2007 数据标识为4字节：DI3 DI2 DI1 DI0
// DI3: 00-电能量, 01-需量, 02-变量数据, 03-事件, 04-参变量, 05-冻结, 06-负荷记录

// 电能量数据标识 (DI3=00)
var (
	DATA_ID_ENERGY_COMBINED  = []byte{0x00, 0x00, 0x00, 0x00} // 组合有功总电能
	DATA_ID_ENERGY_POSITIVE  = []byte{0x00, 0x01, 0x00, 0x00} // 正向有功总电能
	DATA_ID_ENERGY_REVERSE   = []byte{0x00, 0x02, 0x00, 0x00} // 反向有功总电能
	DATA_ID_ENERGY_REACTIVE_COMBINED = []byte{0x00, 0x03, 0x00, 0x00} // 组合无功总电能
)

// 变量数据标识 (DI3=02)
var (
	// 电压 (DI2=01)
	DATA_ID_VOLTAGE_A  = []byte{0x02, 0x01, 0x01, 0x00} // A相电压
	DATA_ID_VOLTAGE_B  = []byte{0x02, 0x01, 0x02, 0x00} // B相电压
	DATA_ID_VOLTAGE_C  = []byte{0x02, 0x01, 0x03, 0x00} // C相电压
	
	// 电流 (DI2=02)
	DATA_ID_CURRENT_A  = []byte{0x02, 0x02, 0x01, 0x00} // A相电流
	DATA_ID_CURRENT_B  = []byte{0x02, 0x02, 0x02, 0x00} // B相电流
	DATA_ID_CURRENT_C  = []byte{0x02, 0x02, 0x03, 0x00} // C相电流
	
	// 瞬时有功功率 (DI2=03)
	DATA_ID_POWER_ACTIVE_A = []byte{0x02, 0x03, 0x01, 0x00} // A相有功功率
	DATA_ID_POWER_ACTIVE_B = []byte{0x02, 0x03, 0x02, 0x00} // B相有功功率
	DATA_ID_POWER_ACTIVE_C = []byte{0x02, 0x03, 0x03, 0x00} // C相有功功率
	DATA_ID_POWER_ACTIVE_TOTAL = []byte{0x02, 0x03, 0x00, 0x00} // 总有功功率
	
	// 功率因数 (DI2=06)
	DATA_ID_POWER_FACTOR_A = []byte{0x02, 0x06, 0x01, 0x00} // A相功率因数
	DATA_ID_POWER_FACTOR_TOTAL = []byte{0x02, 0x06, 0x00, 0x00} // 总功率因数
	
	// 电网频率 (DI2=08, 实际是0x80)
	DATA_ID_FREQUENCY = []byte{0x02, 0x80, 0x00, 0x00} // 电网频率
)

// 参变量数据标识 (DI3=04)
var (
	DATA_ID_COMM_ADDR = []byte{0x04, 0x00, 0x04, 0x01} // 通信地址
	DATA_ID_METER_NUM = []byte{0x04, 0x00, 0x04, 0x02} // 表号
)

// 旧版兼容：正向有功
var DATA_0010 = []byte{0x68, 0x11, 0x04, 0x33, 0x33, 0x34, 0x33}

// 组合有功
var DATA_0000 = []byte{0x68, 0x11, 0x04, 0x33, 0x33, 0x33, 0x33}

// 电流数据块
var DATA_22F0 = []byte{0x68, 0x11, 0x04, 0x33, 0x32, 0x35, 0x35}

// 单相表可跳闸，三相表不行【国网？】
// 合闸
var TURN_ON_CL = []byte{0x68, 0x1c, 0x10, 0x35, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x4f, 0x33}

// 跳闸
var TURN_OFF_CL = []byte{0x68, 0x1c, 0x10, 0x35, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x4d, 0x33}

// 单相表和三相表， 均可跳闸和合闸
// 合闸
var TURN_ON = []byte{0x68, 0x1c, 0x10, 0x35, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x4e, 0x33}

// 跳闸
var TURN_OFF = []byte{0x68, 0x1c, 0x10, 0x35, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x4d, 0x33}

// ==================== 报文构建函数 ====================

// BuildReadDataPacket 构建读数据报文（通用）
// addr: 设备地址（12位十六进制字符串）
// dataID: 数据标识（4字节）
func BuildReadDataPacket(addr string, dataID []byte) []byte {
	if len(dataID) != 4 {
		return nil
	}
	
	buf := bytes.Buffer{}
	buf.WriteByte(0x68) // 起始符
	buf.WriteByte(0x11) // 控制码：读数据
	buf.WriteByte(0x04) // 数据长度
	
	// 数据标识编码（+0x33）
	for _, b := range dataID {
		buf.WriteByte(b + 0x33)
	}
	
	return buildPacket(addr, buf.Bytes())
}

// BuildWriteDataPacket 构建写数据报文（通用）
// addr: 设备地址（12位十六进制字符串）
// dataID: 数据标识（4字节）
// data: 要写入的数据
func BuildWriteDataPacket(addr string, dataID []byte, data []byte) []byte {
	if len(dataID) != 4 {
		return nil
	}
	
	buf := bytes.Buffer{}
	buf.WriteByte(0x68) // 起始符
	buf.WriteByte(0x14) // 控制码：写数据
	buf.WriteByte(byte(4 + len(data))) // 数据长度 = 数据标识(4) + 数据
	
	// 数据标识编码（+0x33）
	for _, b := range dataID {
		buf.WriteByte(b + 0x33)
	}
	
	// 数据编码（+0x33）
	for _, b := range data {
		buf.WriteByte(b + 0x33)
	}
	
	return buildPacket(addr, buf.Bytes())
}

// BuildControlPacket 构建控制命令报文（拉合闸）
// addr: 设备地址
// dataID: 数据标识（4字节）
// operCode: 操作码（如开闸/关闸）
func BuildControlPacket(addr string, dataID []byte, operCode byte, password []byte) []byte {
	if len(dataID) != 4 {
		return nil
	}
	
	// 默认密码（如果未提供）
	if len(password) == 0 {
		password = []byte{0x00, 0x00, 0x00, 0x00}
	}
	if len(password) != 4 {
		return nil
	}
	
	// 获取当前时间（ssmmHHddMMyy）
	timeBytes := fmt_ssmmhhddmmyy()
	
	buf := bytes.Buffer{}
	buf.WriteByte(0x68) // 起始符
	buf.WriteByte(0x1C) // 控制码：控制命令
	buf.WriteByte(byte(4 + 1 + 4 + len(timeBytes))) // 数据长度 = 数据标识(4) + 操作码(1) + 密码(4) + 时间(6)
	
	// 数据标识编码（+0x33）
	for _, b := range dataID {
		buf.WriteByte(b + 0x33)
	}
	
	// 操作码编码（+0x33）
	buf.WriteByte(operCode + 0x33)
	
	// 密码编码（+0x33）
	for _, b := range password {
		buf.WriteByte(b + 0x33)
	}
	
	// 时间（已经编码）
	buf.Write(timeBytes)
	
	return buildPacket(addr, buf.Bytes())
}

// BuildReplyPacket 构建应答报文（通用）
// addr: 设备地址
// controlCode: 控制码（应答码，如 0x91）
// dataID: 数据标识（4字节）
// data: 应答数据
func BuildReplyPacket(addr string, controlCode byte, dataID []byte, data []byte) []byte {
	if len(dataID) != 4 {
		return nil
	}
	
	buf := bytes.Buffer{}
	buf.WriteByte(0x68)       // 起始符
	buf.WriteByte(controlCode) // 控制码（应答）
	buf.WriteByte(byte(4 + len(data))) // 数据长度
	
	// 数据标识编码（+0x33）
	for _, b := range dataID {
		buf.WriteByte(b + 0x33)
	}
	
	// 数据编码（+0x33）
	for _, b := range data {
		buf.WriteByte(b + 0x33)
	}
	
	return buildPacket(addr, buf.Bytes())
}

// 读取正向有功总电能
func ReadPacket0010(addr string) []byte {
	return BuildReadDataPacket(addr, DATA_ID_ENERGY_POSITIVE)
}

// 读取组合有功总电能
func ReadPacket0000(addr string) []byte {
	return BuildReadDataPacket(addr, DATA_ID_ENERGY_COMBINED)
}

// 读取三相电流
func ReadPacket0F22(addr string) []byte {
	// 这个实际应该读取电流数据块，但原实现不标准，保持兼容
	return buildPacket(addr, DATA_22F0)
}

// ReadVoltageA 读取A相电压
func ReadVoltageA(addr string) []byte {
	return BuildReadDataPacket(addr, DATA_ID_VOLTAGE_A)
}

// ReadCurrentA 读取A相电流
func ReadCurrentA(addr string) []byte {
	return BuildReadDataPacket(addr, DATA_ID_CURRENT_A)
}

// ReadPowerA 读取A相有功功率
func ReadPowerA(addr string) []byte {
	return BuildReadDataPacket(addr, DATA_ID_POWER_ACTIVE_A)
}

// ReadFrequency 读取电网频率
func ReadFrequency(addr string) []byte {
	return BuildReadDataPacket(addr, DATA_ID_FREQUENCY)
}

// ReadCommAddr 读取通信地址
func ReadCommAddr(addr string) []byte {
	buf := bytes.Buffer{}
	buf.WriteByte(0x68) // 起始符
	buf.WriteByte(0x13) // 控制码：读通信地址
	buf.WriteByte(0x00) // 数据长度为0
	
	return buildPacket(addr, buf.Bytes())
}

// 合闸报文
func TurnOnPacket(addr string) []byte {
	buf := bytes.Buffer{}
	buf.Write(TURN_ON)
	buf.Write(fmt_ssmmhhddmmyy())

	// CL 没作用
	if addr[0:2] == "04" {
		buf = bytes.Buffer{}
		buf.Write(TURN_ON_CL)
		buf.Write(fmt_ssmmhhddmmyy())
	}

	lg.Debug(utils.HexTool.ToHexString(buildPacket(addr, buf.Bytes())))
	return buildPacket(addr, buf.Bytes())
}

// 跳闸报文
func TurnOffPacket(addr string) []byte {
	buf := bytes.Buffer{}
	buf.Write(TURN_OFF)
	buf.Write(fmt_ssmmhhddmmyy())

	lg.Debug(utils.HexTool.ToHexString(buildPacket(addr, buf.Bytes())))
	return buildPacket(addr, buf.Bytes())
}

func fmt_ssmmhhddmmyy() []byte {
	// ssmmHHddMMyy
	// 06-01-02 15:04:05
	dt := time.Now().Add(time.Hour * 1).Format("050415020106")
	data := utils.HexTool.ToBytes(dt)
	for n, _ := range data {
		data[n] = data[n] + 0x33
	}
	return data
}

func ParsePacket(bs []byte) DataResult {
	ret := DataResult{
		Flag: false,
	}

	// 去掉前导FE
	data := utils.HexTool.ClearFE(bs)
	
	// 基本格式检查: 起始符(1) + 地址(6) + 起始符(1) + 控制码(1) + 长度(1) + ... + 校验(1) + 结束符(1)
	// 最小长度: 12字节
	if len(data) < 12 {
		lg.Debug("报文长度不足")
		return ret
	}

	// 检查起始符和结束符
	if data[0] != 0x68 || data[7] != 0x68 || data[len(data)-1] != 0x16 {
		lg.Debug("起始符或结束符错误")
		return ret
	}

	// 解析地址域 (6字节，BCD码，低字节在前)
	ret.DeviceCode = utils.HexTool.ToHexString(utils.HexTool.BytesReverse(data[1:7]))

	// 解析控制码
	controlCode := data[8]
	ret.ControlCode = controlCode

	// 解析数据长度
	dataLen := int(data[9])
	ret.DataLen = dataLen

	// 验证数据长度
	expectedLen := 12 + dataLen // 起始(1) + 地址(6) + 起始(1) + 控制(1) + 长度(1) + 数据(dataLen) + 校验(1) + 结束(1)
	if len(data) != expectedLen {
		lg.Debugf("数据长度不匹配: 期望%d, 实际%d", expectedLen, len(data))
		return ret
	}

	// 校验和验证
	calcChecksum := byte(0)
	for i := 0; i < len(data)-2; i++ {
		calcChecksum += data[i]
	}
	if calcChecksum != data[len(data)-2] {
		lg.Debugf("校验和错误: 计算值0x%02X, 实际值0x%02X", calcChecksum, data[len(data)-2])
		return ret
	}

	// 提取数据域（如果有）
	var dataField []byte
	if dataLen > 0 {
		dataField = make([]byte, dataLen)
		copy(dataField, data[10:10+dataLen])
		// 数据域解码（减0x33）
		for i := range dataField {
			dataField[i] -= 0x33
		}
	}

	// 判断是请求帧还是应答帧
	if (controlCode & 0x80) == 0 {
		// 请求帧 (控制码最高位为0)
		ret.IsRequest = true
		ret.Flag = true
		ret.DataType = 3 // 请求帧类型
		
		switch controlCode {
		case 0x11:
			ret.FrameType = "读数据"
			if dataLen >= 4 {
				ret.DataID = utils.HexTool.ToHexString(dataField[0:4])
			}
		case 0x12:
			ret.FrameType = "读后续数据"
			if dataLen >= 4 {
				ret.DataID = utils.HexTool.ToHexString(dataField[0:4])
			}
		case 0x13:
			ret.FrameType = "读通信地址"
		case 0x14:
			ret.FrameType = "写数据"
			if dataLen >= 4 {
				ret.DataID = utils.HexTool.ToHexString(dataField[0:4])
			}
		case 0x15:
			ret.FrameType = "写通信地址"
		case 0x16:
			ret.FrameType = "冻结命令"
		case 0x17:
			ret.FrameType = "更改通信速率"
		case 0x18:
			ret.FrameType = "修改密码"
		case 0x19:
			ret.FrameType = "最大需量清零"
		case 0x1A:
			ret.FrameType = "电表清零"
		case 0x1B:
			ret.FrameType = "事件清零"
		case 0x1C:
			ret.FrameType = "控制命令(拉合闸)"
			if dataLen >= 4 {
				ret.DataID = utils.HexTool.ToHexString(dataField[0:4])
			}
		default:
			ret.FrameType = fmt.Sprintf("未知请求(0x%02X)", controlCode)
		}
	} else {
		// 应答帧 (控制码最高位为1)
		ret.IsResponse = true
		ret.Flag = true
		
		switch controlCode {
		case 0x91:
			ret.FrameType = "读数据应答"
			if dataLen >= 4 {
				ret.DataID = utils.HexTool.ToHexString(dataField[0:4])
				ret.DataIDDesc = getDataIDDesc(dataField[0:4])
				
				// 根据数据标识解析数据内容
				if dataLen > 4 {
					di3 := dataField[0]
					di2 := dataField[1]
					
					switch di3 {
					case 0x00: // 电能量数据
						ret.DataType = 0
						if dataLen >= 8 {
							ret.Data = parseEnergy(dataField[4:8])
						}
						
					case 0x02: // 变量数据
						switch di2 {
						case 0x01: // 电压
							ret.DataType = 4
							if dataLen >= 6 {
								ret.Va = parseVoltage(dataField[4:6])
							}
							if dataLen >= 8 {
								ret.Vb = parseVoltage(dataField[6:8])
							}
							if dataLen >= 10 {
								ret.Vc = parseVoltage(dataField[8:10])
							}
							
						case 0x02: // 电流
							ret.DataType = 2
							if dataLen >= 7 {
								ret.Ia = parseCurrent(dataField[4:7])
							}
							if dataLen >= 10 {
								ret.Ib = parseCurrent(dataField[7:10])
							}
							if dataLen >= 13 {
								ret.Ic = parseCurrent(dataField[10:13])
							}
							
						case 0x03: // 有功功率
							ret.DataType = 5
							if dataLen >= 7 {
								ret.Pa = parsePower(dataField[4:7])
							}
							if dataLen >= 10 {
								ret.Pb = parsePower(dataField[7:10])
							}
							if dataLen >= 13 {
								ret.Pc = parsePower(dataField[10:13])
							}
							
						case 0x06: // 功率因数
							if dataLen >= 6 {
								ret.PowerFactor = parsePowerFactor(dataField[4:6])
							}
							
						case 0x80: // 频率
							ret.DataType = 6
							if dataLen >= 6 {
								ret.Frequency = parseFrequency(dataField[4:6])
							}
						}
					}
				}
			}
		case 0x92:
			ret.FrameType = "读后续数据应答"
		case 0x93:
			ret.FrameType = "读通信地址应答"
		case 0x94:
			ret.FrameType = "写数据应答"
		case 0x9C:
			ret.FrameType = "控制命令应答(拉合闸成功)"
			ret.DataType = 1
			ret.TurnResult = true
		case 0xDC:
			ret.FrameType = "控制命令应答(拉合闸失败)"
			ret.DataType = 1
			ret.TurnResult = false
		default:
			// 检查是否为异常应答
			if (controlCode & 0x40) != 0 {
				ret.FrameType = fmt.Sprintf("异常应答(0x%02X)", controlCode)
			} else {
				ret.FrameType = fmt.Sprintf("未知应答(0x%02X)", controlCode)
			}
		}
	}

	return ret
}

// ==================== 数据解析辅助函数 ====================

// parseBCDValue 通用BCD码解析函数
func parseBCDValue(bs []byte, resolution float64) float64 {
	if len(bs) == 0 {
		return 0.0
	}
	
	// 1. 翻转（低字节在前）
	data := utils.HexTool.BytesReverse(bs)
	// 2. 转hex字符串
	valStr := utils.HexTool.ToHexString(data)
	// 3. 转整数
	num, err := strconv.ParseInt(valStr, 10, 64)
	if err != nil {
		return 0.0
	}
	// 4. 乘以分辨率
	ret := resolution * float64(num)
	// 5. 保留04位小数
	ret, _ = strconv.ParseFloat(fmt.Sprintf("%.4f", ret), 64)
	return ret
}

// parseEnergy 解析电能量数据 (4字节，单位0.01kWh)
func parseEnergy(bs []byte) float64 {
	return parseBCDValue(bs, 0.01)
}

// parseVoltage 解析电压数据 (2字节，单位0.1V)
func parseVoltage(bs []byte) float64 {
	return parseBCDValue(bs, 0.1)
}

// parseCurrent 解析电流数据 (3字节，单位0.001A)
func parseCurrent(bs []byte) float64 {
	return parseBCDValue(bs, 0.001)
}

// parsePower 解析功率数据 (3字节，单位0.0001kW)
func parsePower(bs []byte) float64 {
	return parseBCDValue(bs, 0.0001)
}

// parsePowerFactor 解析功率因数 (2字节，单位0.001)
func parsePowerFactor(bs []byte) float64 {
	return parseBCDValue(bs, 0.001)
}

// parseFrequency 解析频率数据 (2字节，单位0.01Hz)
func parseFrequency(bs []byte) float64 {
	return parseBCDValue(bs, 0.01)
}

// getDataIDDesc 获取数据标识描述
func getDataIDDesc(dataID []byte) string {
	if len(dataID) != 4 {
		return "未知数据标识"
	}
	
	di3, di2, di1 := dataID[0], dataID[1], dataID[2]
	
	switch di3 {
	case 0x00: // 电能量
		switch di2 {
		case 0x00:
			return "组合有功总电能"
		case 0x01:
			return "正向有功总电能"
		case 0x02:
			return "反向有功总电能"
		case 0x03:
			return "组合无功总电能"
		default:
			return fmt.Sprintf("电能量数据(DI2=%02X)", di2)
		}
		
	case 0x02: // 变量数据
		switch di2 {
		case 0x01: // 电压
			switch di1 {
			case 0x01:
				return "A相电压"
			case 0x02:
				return "B相电压"
			case 0x03:
				return "C相电压"
			default:
				return "电压数据"
			}
		case 0x02: // 电流
			switch di1 {
			case 0x01:
				return "A相电流"
			case 0x02:
				return "B相电流"
			case 0x03:
				return "C相电流"
			default:
				return "电流数据"
			}
		case 0x03: // 有功功率
			switch di1 {
			case 0x00:
				return "总有功功率"
			case 0x01:
				return "A相有功功率"
			case 0x02:
				return "B相有功功率"
			case 0x03:
				return "C相有功功率"
			default:
				return "有功功率数据"
			}
		case 0x06:
			return "功率因数"
		case 0x80:
			return "电网频率"
		default:
			return fmt.Sprintf("变量数据(DI2=%02X)", di2)
		}
		
	case 0x04: // 参变量
		if bytes.Equal(dataID, DATA_ID_COMM_ADDR) {
			return "通信地址"
		}
		if bytes.Equal(dataID, DATA_ID_METER_NUM) {
			return "表号"
		}
		return "参变量数据"
		
	default:
		return fmt.Sprintf("未知数据标识(DI3=%02X)", di3)
	}
}

// 保留原 currentBlock 函数，保持兼容
func currentBlock(bs []byte) float64 {
	return parseCurrent(bs)
}

// 123456.78 ==> ab896745[hex]
func WriteBCDValue(val float64) []byte {
	str := fmt.Sprintf("00000000%.0f", val*100)
	str = str[len(str)-8:]
	data := utils.HexTool.ToBytes(str)
	data = utils.HexTool.BytesReverse(data)
	for n, _ := range data {
		data[n] = data[n] + 0x33
	}
	return data
}

// MeterValue 保留原函数，保持兼容
func MeterValue(bs []byte) float64 {
	return parseEnergy(bs)
}

func buildPacket(addr string, data []byte) []byte {
	buf := bytes.Buffer{}
	buf.WriteByte(0x68)
	buf.Write(utils.HexTool.BytesReverse(utils.HexTool.ToBytes(addr)))
	buf.Write(data)
	buf.WriteByte(utils.HexTool.CheckSum(buf.Bytes()))
	buf.WriteByte(0x16)

	return buf.Bytes()
}
