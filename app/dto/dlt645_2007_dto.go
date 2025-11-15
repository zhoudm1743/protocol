package dto

import (
	"fmt"
	dlt645_2007 "protocol/protocol/dlt645-2007"
	"time"
)

// BuildDlt645_2007Request 构建请求DTO
type BuildDlt645_2007Request struct {
	Addr      string `json:"addr" binding:"required"`      // 地址（12位十六进制字符串，6字节）
	FrameType string `json:"frameType" binding:"required"` // 帧类型：read_0010-读正向有功，read_0000-读组合有功，read_0f22-读电流，turn_on-合闸，turn_off-跳闸
	DataID    string `json:"dataId,omitempty"`             // 数据标识（用于write_data，4字节十六进制）
	WriteData string `json:"writeData,omitempty"`          // 写入数据（用于write_data，十六进制）
}

// SimulateDlt645_2007Request 模拟请求DTO
type SimulateDlt645_2007Request struct {
	Addr       string  `json:"addr" binding:"required"`     // 地址（12位十六进制字符串）
	MeterData  float64 `json:"meterData,omitempty"`         // 电能数据（kWh）
	Ia         float64 `json:"ia,omitempty"`                // A相电流（A）
	Ib         float64 `json:"ib,omitempty"`                // B相电流（A）
	Ic         float64 `json:"ic,omitempty"`                // C相电流（A）
	ConnType   string  `json:"connType" binding:"required"` // 连接类型: serial/tcp_server/tcp_client
	SerialPort string  `json:"serialPort,omitempty"`        // 串口设备
	BaudRate   int     `json:"baudRate,omitempty"`          // 波特率（默认2400）
	TCPAddress string  `json:"tcpAddress,omitempty"`        // TCP地址（格式: host:port）
	Reconnect  bool    `json:"reconnect,omitempty"`         // 是否自动重连（tcp_client）
}

// Dlt645_2007Response 帧响应DTO
type Dlt645_2007Response struct {
	Success   bool              `json:"success"`   // 是否成功
	Message   string            `json:"message"`   // 消息
	HexData   string            `json:"hexData"`   // 十六进制数据
	Frame     *Dlt645_2007DTO   `json:"frame"`     // 解析后的帧信息
	Timestamp time.Time         `json:"timestamp"` // 时间戳
}

// Dlt645_2007DTO 帧信息DTO
type Dlt645_2007DTO struct {
	DeviceCode   string  `json:"deviceCode"`            // 设备地址
	DataType     int     `json:"dataType"`              // 数据类型：0-电能，1-拉合闸，2-电流，3-请求帧，4-电压，5-功率，6-频率
	Flag         bool    `json:"flag"`                  // 解析成功标志
	Data         float64 `json:"data,omitempty"`        // 电能数据（dataType=0）
	TurnResult   bool    `json:"turnResult,omitempty"`  // 拉合闸结果（dataType=1）
	Ia           float64 `json:"ia,omitempty"`          // A相电流（dataType=2）
	Ib           float64 `json:"ib,omitempty"`          // B相电流（dataType=2）
	Ic           float64 `json:"ic,omitempty"`          // C相电流（dataType=2）
	Va           float64 `json:"va,omitempty"`          // A相电压（dataType=4）
	Vb           float64 `json:"vb,omitempty"`          // B相电压（dataType=4）
	Vc           float64 `json:"vc,omitempty"`          // C相电压（dataType=4）
	Pa           float64 `json:"pa,omitempty"`          // A相有功功率（dataType=5）
	Pb           float64 `json:"pb,omitempty"`          // B相有功功率（dataType=5）
	Pc           float64 `json:"pc,omitempty"`          // C相有功功率（dataType=5）
	Frequency    float64 `json:"frequency,omitempty"`   // 频率（dataType=6）
	PowerFactor  float64 `json:"powerFactor,omitempty"` // 功率因数
	ControlCode  string  `json:"controlCode"`           // 控制码（十六进制）
	DataLen      int     `json:"dataLen"`               // 数据长度
	DataID       string  `json:"dataId,omitempty"`      // 数据标识（十六进制字符串）
	DataIDDesc   string  `json:"dataIdDesc,omitempty"`  // 数据标识描述
	IsRequest    bool    `json:"isRequest"`             // 是否为请求帧
	IsResponse   bool    `json:"isResponse"`            // 是否为应答帧
	FrameType    string  `json:"frameType"`             // 帧类型描述
	DataTypeName string  `json:"dataTypeName"`          // 数据类型名称
	Timestamp    string  `json:"timestamp"`             // 时间戳字符串
}

// ToDlt645_2007DTO 将 DataResult 转换为 Dlt645_2007DTO
func ToDlt645_2007DTO(result *dlt645_2007.DataResult) *Dlt645_2007DTO {
	dto := &Dlt645_2007DTO{
		DeviceCode:   result.DeviceCode,
		DataType:     result.DataType,
		Flag:         result.Flag,
		ControlCode:  fmt.Sprintf("0x%02X", result.ControlCode),
		DataLen:      result.DataLen,
		DataID:       result.DataID,
		IsRequest:    result.IsRequest,
		IsResponse:   result.IsResponse,
		FrameType:    result.FrameType,
		DataTypeName: getDataTypeName(result.DataType),
		Timestamp:    time.Now().Format("2006-01-02 15:04:05"),
	}

	// 根据数据类型填充不同的字段
	switch result.DataType {
	case 0: // 电能
		dto.Data = result.Data
	case 1: // 拉合闸
		dto.TurnResult = result.TurnResult
	case 2: // 电流
		dto.Ia = result.Ia
		dto.Ib = result.Ib
		dto.Ic = result.Ic
	case 3: // 请求帧
		// 请求帧不需要额外数据
	case 4: // 电压
		dto.Va = result.Va
		dto.Vb = result.Vb
		dto.Vc = result.Vc
	case 5: // 功率
		dto.Pa = result.Pa
		dto.Pb = result.Pb
		dto.Pc = result.Pc
	case 6: // 频率
		dto.Frequency = result.Frequency
	}
	
	// 填充功率因数和数据标识描述
	dto.PowerFactor = result.PowerFactor
	dto.DataIDDesc = result.DataIDDesc

	return dto
}

// getDataTypeName 获取数据类型名称
func getDataTypeName(dataType int) string {
	switch dataType {
	case 0:
		return "电能数据"
	case 1:
		return "拉合闸操作"
	case 2:
		return "电流数据"
	case 3:
		return "请求帧"
	case 4:
		return "电压数据"
	case 5:
		return "功率数据"
	case 6:
		return "频率数据"
	default:
		return fmt.Sprintf("未知类型 (%d)", dataType)
	}
}
