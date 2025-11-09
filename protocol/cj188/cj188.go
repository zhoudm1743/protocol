// Package cj188 实现CJ/T188-2004协议（户用计量仪表数据传输技术条件）
// 参考文档：水气表下行通信规约188 V1.1标准版
// 协议特点：
// 1. 主-从模式的半双工通讯方式
// 2. 字节格式：8位数据位 + 1位起始位(0) + 1位偶校验位 + 1位停止位(1)，共11位
// 3. 通讯波特率：2400 bps
// 4. 校验码：从起始符(0x68)开始到校验码之前的所有字节和的模256
// 5. 地址编码：采用BCD码格式，7字节（A0-A6）
// 6. 数据编码：采用BCD码格式，小端序存储
package cj188

import (
	"fmt"
	"protocol/utils"
	"time"
)

var (
	TYPE_WATER       = 0x10
	TYPE_GAS         = 0x30
	TYPE_ELECTRICITY = 0x40
)

type Cj188Frame struct {
	Prefix   byte   // 1byte
	Type     byte   // 1byte
	Addr     string // 7byte
	Control  byte   // 1byte
	Len      int    // 1byte 数据域长度
	DataID   []byte // 2byte 数据域标识 901F/1F90
	Serial   byte   // 1byte 序号
	Checksum byte   // 1byte 校验和

	Data      []byte    // 数据域
	Unit      byte      // 1byte 单位
	Status    byte      // 1byte 状态
	Timestamp time.Time // 时间戳
}

// GetFlowData 获取累积流量值（4字节，BCD码，小端序）
// 根据协议文档，累积流量采用BCD码格式，小端序存储
// 例如：[0x10, 0x00, 0x10, 0x00] 表示 10001000（BCD码，小端序）
func (f *Cj188Frame) GetFlowData() uint32 {
	if f.Control != CTRL_REPLY || len(f.Data) < 7 {
		return 0
	}
	// 累积流量在数据域中的位置：数据标识(2) + 序列号(1) = 索引3开始
	// 累积流量是BCD码格式，小端序存储：[D0, D1, D2, D3]
	flowBytes := f.Data[3:7]
	return utils.HexTool.BCDToUint32(flowBytes)
}

// GetValveStatus 获取阀门状态
// 状态字S0的D0-D1位：00-开阀，01-关阀，10-异常，11-未知
func (f *Cj188Frame) GetValveStatus() int {
	if len(f.Data) < 8 {
		return -1
	}
	status0 := f.Data[7]
	return int(status0 & 0x03)
}

// GetBatteryStatus 获取电池电压状态
// 状态字S0的D2位：0-正常，1-欠压
func (f *Cj188Frame) GetBatteryStatus() bool {
	if len(f.Data) < 8 {
		return false
	}
	status0 := f.Data[7]
	return (status0 & 0x04) != 0
}

// GetIT05Status 获取IT05状态
// 状态字S0的D6位：0-正常，1-异常
func (f *Cj188Frame) GetIT05Status() bool {
	if len(f.Data) < 8 {
		return false
	}
	status0 := f.Data[7]
	return (status0 & 0x40) != 0
}

// GetAlarmStatus 获取报警器状态
// 状态字S0的D6-D7位：00-报警，01-上电，11-未上电
// 注意：D6位同时用于IT05状态，D6-D7组合用于报警器状态
func (f *Cj188Frame) GetAlarmStatus() int {
	if len(f.Data) < 8 {
		return -1
	}
	status0 := f.Data[7]
	// 读取D6-D7位（右移6位后取低2位）
	return int((status0 >> 6) & 0x03)
}

const (
	FRAME_START          = 0x68 // 帧起始符
	FRAME_END            = 0x16 // 帧结束符
	CTRL_READ            = 0x01 // 读数据控制码
	CTRL_REPLY           = 0x81 // 应答控制码
	CTRL_CLOSE_VALVE     = 0x2A // 关阀控制码
	CTRL_OPEN_VALVE      = 0x2B // 开阀控制码
	CTRL_SET_PARAM       = 0x2C // 设置参数控制码
	CTRL_REPLY_CLOSE     = 0xA5 // 关阀应答控制码
	CTRL_REPLY_OPEN      = 0xA6 // 开阀应答控制码
	CTRL_REPLY_SET_PARAM = 0xA7 // 设置参数应答控制码
)

// Parser188 解析CJ188协议帧
func Parser188(data []byte) (*Cj188Frame, error) {
	var ret Cj188Frame
	ret.Timestamp = time.Now()

	// 1. 去除前缀0xFE
	data = utils.HexTool.ClearFE(data)
	if len(data) < 16 {
		return nil, fmt.Errorf("无效的帧长度: %d", len(data))
	}

	// 2. 检查帧起始符
	if data[0] != FRAME_START {
		return nil, fmt.Errorf("无效的帧起始符: 0x%02X", data[0])
	}
	ret.Prefix = data[0]

	// 3. 解析表计类型
	ret.Type = data[1]

	// 4. 解析地址（7字节，地址是BCD码，需要反向读取并转换为十进制字符串）
	addrBytes := data[2:9]
	ret.Addr = utils.HexTool.BCDToDecimal(addrBytes)

	// 5. 解析控制码
	ret.Control = data[9]

	// 6. 解析数据域长度
	ret.Len = int(data[10])

	// 7. 检查最小长度（查询帧至少16字节，应答帧根据数据域长度变化）
	minLen := 16
	if ret.Control == CTRL_REPLY {
		minLen = 11 + ret.Len + 2 // 11字节固定部分 + 数据域长度 + 校验和(1) + 结束符(1)
	}
	if len(data) < minLen {
		return nil, fmt.Errorf("帧长度不足: 需要%d字节，实际%d字节", minLen, len(data))
	}

	// 8. 解析数据标识（2字节）
	ret.DataID = make([]byte, 2)
	ret.DataID[0] = data[11]
	ret.DataID[1] = data[12]

	// 9. 根据控制码解析数据域
	switch ret.Control {
	case CTRL_REPLY:
		// 应答帧：解析数据域
		// 数据域从第11字节开始（数据标识），长度为L字节
		// 数据域格式：数据标识(2) + 序列号(1) + 累积流量(4) + 状态0(1) + 状态1(1) = 9字节
		dataStart := 11
		dataEnd := dataStart + ret.Len
		if dataEnd > len(data) {
			return nil, fmt.Errorf("数据域长度超出帧长度")
		}
		ret.Data = make([]byte, ret.Len)
		copy(ret.Data, data[dataStart:dataEnd])

		// 解析序列号（数据域中第3个字节，索引2）
		if ret.Len >= 3 {
			ret.Serial = ret.Data[2]
		}

		// 解析累积流量（D0-D3，4字节，小端序）
		// 累积流量在数据域中的位置：数据标识(2) + 序列号(1) = 索引3开始
		// 累积流量已存储在ret.Data[3:7]中，由GetFlowData()方法处理小端序转换

		// 解析状态（状态0在数据域中索引7，状态1在索引8）
		if ret.Len >= 8 {
			ret.Status = ret.Data[7]
		}
	case CTRL_READ:
		// 查询帧：解析序列号（固定位置）
		ret.Serial = data[13]
		// 查询帧：无数据域
		ret.Data = nil
	case CTRL_CLOSE_VALVE, CTRL_OPEN_VALVE, CTRL_SET_PARAM:
		// 控制指令帧：解析序列号和数据域
		if ret.Len > 0 {
			dataStart := 11
			dataEnd := dataStart + ret.Len
			if dataEnd > len(data) {
				return nil, fmt.Errorf("数据域长度超出帧长度")
			}
			ret.Data = make([]byte, ret.Len)
			copy(ret.Data, data[dataStart:dataEnd])
			// 控制指令帧的序列号通常在数据域的第一个字节
			if ret.Len >= 1 {
				ret.Serial = ret.Data[0]
			}
		} else {
			// 无数据域的控制指令，序列号在固定位置
			if len(data) > 13 {
				ret.Serial = data[13]
			}
			ret.Data = nil
		}
	case CTRL_REPLY_CLOSE, CTRL_REPLY_OPEN, CTRL_REPLY_SET_PARAM:
		// 控制指令应答帧：解析数据域
		// 数据域格式：操作码(1) + 序列号(1) + 保留(2) + 执行结果(1) = 5字节
		dataStart := 11
		dataEnd := dataStart + ret.Len
		if dataEnd > len(data) {
			return nil, fmt.Errorf("数据域长度超出帧长度")
		}
		ret.Data = make([]byte, ret.Len)
		copy(ret.Data, data[dataStart:dataEnd])

		// 解析序列号（数据域中第2个字节，索引1）
		if ret.Len >= 2 {
			ret.Serial = ret.Data[1]
		}
	default:
		// 未知控制码，返回错误
		return nil, fmt.Errorf("未知的控制码: 0x%02X", ret.Control)
	}

	// 11. 计算校验和位置
	// 查询帧：固定位置14（序列号之后）
	// 应答帧：数据域结束之后（11 + L）
	checksumPos := 11 + ret.Len
	if ret.Control == CTRL_READ {
		checksumPos = 14
	}

	// 12. 验证校验和
	if checksumPos >= len(data) {
		return nil, fmt.Errorf("校验和位置超出帧长度")
	}
	ret.Checksum = data[checksumPos]

	// 计算校验和（从帧起始符到数据域结束，不包括校验和本身）
	calcStart := 0
	calcEnd := checksumPos
	calcData := data[calcStart:calcEnd]
	calcSum := utils.HexTool.CheckSum(calcData)
	if calcSum != ret.Checksum {
		return nil, fmt.Errorf("校验和错误: 计算值0x%02X, 实际值0x%02X", calcSum, ret.Checksum)
	}

	// 13. 检查帧结束符
	endPos := checksumPos + 1
	if endPos >= len(data) {
		return nil, fmt.Errorf("帧结束符位置超出帧长度")
	}
	if data[endPos] != FRAME_END {
		return nil, fmt.Errorf("无效的帧结束符: 0x%02X", data[endPos])
	}

	return &ret, nil
}

// Build188 构建CJ188协议查询帧
func Build188(meterType byte, addr string, dataID []byte, serial byte) ([]byte, error) {
	// 1. 将十进制地址字符串转换为7字节BCD码
	addrBytes, err := utils.HexTool.DecimalToBCD(addr, 7)
	if err != nil {
		return nil, fmt.Errorf("地址转换失败: %v", err)
	}

	// 2. 验证数据标识长度
	if len(dataID) != 2 {
		return nil, fmt.Errorf("数据标识长度错误: 需要2字节，实际%d字节", len(dataID))
	}

	// 3. 构建帧（查询帧固定格式）
	frame := make([]byte, 0, 16)
	frame = append(frame, FRAME_START)  // 帧起始符
	frame = append(frame, meterType)    // 表计类型
	frame = append(frame, addrBytes...) // 地址（7字节）
	frame = append(frame, CTRL_READ)    // 控制码
	frame = append(frame, 0x03)         // 数据域长度（查询帧固定为3）
	frame = append(frame, dataID...)    // 数据标识（2字节）
	frame = append(frame, serial)       // 序列号

	// 4. 计算校验和（从帧起始符到序列号）
	checksum := utils.HexTool.CheckSum(frame)
	frame = append(frame, checksum)  // 校验和
	frame = append(frame, FRAME_END) // 帧结束符

	return frame, nil
}

// Build188Reply 构建CJ188协议应答帧
// 根据数据标识构建完整的数据域：
// - 901F (1F 90): 数据标识(2) + 序列号(1) + 当前累积流量(4) + 单位(1) + 日累积流量(4) + 单位(1) + 实时时间(7) + 表计状态(1) = 22字节
func Build188Reply(meterType byte, addr string, dataID []byte, serial byte, flowData []byte, status byte) ([]byte, error) {
	// 1. 将十进制地址字符串转换为7字节BCD码
	addrBytes, err := utils.HexTool.DecimalToBCD(addr, 7)
	if err != nil {
		return nil, fmt.Errorf("地址转换失败: %v", err)
	}

	// 2. 验证数据标识长度
	if len(dataID) != 2 {
		return nil, fmt.Errorf("数据标识长度错误: 需要2字节，实际%d字节", len(dataID))
	}

	// 3. 验证累积流量长度
	if len(flowData) != 4 {
		return nil, fmt.Errorf("累积流量数据长度错误: 需要4字节，实际%d字节", len(flowData))
	}

	// 4. 根据数据标识构建数据域
	// 数据标识901F (1F 90) 的完整数据域结构
	dataIDStr := fmt.Sprintf("%02X%02X", dataID[0], dataID[1])
	var dataField []byte
	var dataLen byte

	if dataIDStr == "1F90" || dataIDStr == "901F" {
		// 数据标识901F：完整数据域（22字节）
		// 数据标识(2) + 序列号(1) + 当前累积流量(4) + 单位(1) + 日累积流量(4) + 单位(1) + 实时时间(7) + 表计状态(1)
		dataLen = 22
		dataField = make([]byte, 0, dataLen)
		dataField = append(dataField, dataID...)   // 数据标识(2)
		dataField = append(dataField, serial)      // 序列号(1)
		dataField = append(dataField, flowData...) // 当前累积流量(4)
		dataField = append(dataField, 0x2C)        // 单位：吨(1)
		dataField = append(dataField, flowData...) // 日累积流量(4) - 使用相同值
		dataField = append(dataField, 0x2C)        // 单位：吨(1)
		// 实时时间(7字节)：年(1) + 月(1) + 日(1) + 时(1) + 分(1) + 秒(1) + 星期(1)
		now := time.Now()
		dataField = append(dataField, byte(now.Year()%100)) // 年（后两位）
		dataField = append(dataField, byte(now.Month()))    // 月
		dataField = append(dataField, byte(now.Day()))      // 日
		dataField = append(dataField, byte(now.Hour()))     // 时
		dataField = append(dataField, byte(now.Minute()))   // 分
		dataField = append(dataField, byte(now.Second()))   // 秒
		dataField = append(dataField, byte(now.Weekday()))  // 星期
		dataField = append(dataField, status)               // 表计状态(1)
	} else {
		// 其他数据标识：简化数据域（9字节）
		// 数据标识(2) + 序列号(1) + 累积流量(4) + 状态0(1) + 状态1(1)
		dataLen = 9
		dataField = make([]byte, 0, dataLen)
		dataField = append(dataField, dataID...)   // 数据标识(2)
		dataField = append(dataField, serial)      // 序列号(1)
		dataField = append(dataField, flowData...) // 累积流量(4)
		dataField = append(dataField, status)      // 状态0(1)
		dataField = append(dataField, 0xFF)        // 状态1(1)
	}

	// 5. 构建帧
	frame := make([]byte, 0, 11+int(dataLen)+2)
	frame = append(frame, FRAME_START)  // 帧起始符
	frame = append(frame, meterType)    // 表计类型
	frame = append(frame, addrBytes...) // 地址（7字节）
	frame = append(frame, CTRL_REPLY)   // 控制码
	frame = append(frame, dataLen)      // 数据域长度
	frame = append(frame, dataField...) // 数据域

	// 6. 计算校验和（从帧起始符到数据域结束）
	checksum := utils.HexTool.CheckSum(frame)
	frame = append(frame, checksum)  // 校验和
	frame = append(frame, FRAME_END) // 帧结束符

	return frame, nil
}
