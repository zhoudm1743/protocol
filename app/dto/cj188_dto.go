package dto

import (
	"fmt"
	"protocol/protocol/cj188"
	"time"
)

// ParseRequest 解析请求DTO
type ParseRequest struct {
	HexData string `json:"hexData" binding:"required"` // 十六进制字符串，例如 "FE FE FE 68 10 77 66 55 44 33 22 11 01 03 90 1F 01 08 16"
}

// BuildRequest 构建请求DTO
type BuildRequest struct {
	MeterType byte   `json:"meterType" binding:"required"` // 表计类型：0x10-水表，0x30-气表，0x40-电表
	Addr      string `json:"addr" binding:"required"`      // 地址（14位十六进制字符串，7字节）
	DataID    string `json:"dataId" binding:"required"`    // 数据标识（4位十六进制字符串，2字节），例如 "901F"
	Serial    byte   `json:"serial"`                       // 序列号（允许为0）
	FrameType string `json:"frameType" binding:"required"` // 帧类型：read-查询帧，reply-应答帧
	// 应答帧专用字段
	FlowData []byte `json:"flowData,omitempty"` // 累积流量（4字节，小端序），例如 [0x78, 0x56, 0x34, 0x12] 表示 0x12345678
	Status   byte   `json:"status,omitempty"`   // 状态字节（默认0x00）
}

// SimulateRequest 模拟请求DTO
type SimulateRequest struct {
	MeterType  byte   `json:"meterType" binding:"required"` // 表计类型
	Addr       string `json:"addr" binding:"required"`      // 地址（十进制字符串）
	FlowData   []byte `json:"flowData,omitempty"`           // 累积流量（4字节BCD码）
	Status     byte   `json:"status,omitempty"`             // 状态字节
	ConnType   string `json:"connType" binding:"required"`  // 连接类型: serial/tcp_server/tcp_client
	SerialPort string `json:"serialPort,omitempty"`         // 串口设备（serial类型需要）
	BaudRate   int    `json:"baudRate,omitempty"`           // 波特率（serial类型需要，默认2400）
	TCPAddress string `json:"tcpAddress,omitempty"`         // TCP地址（tcp_server/tcp_client类型需要，格式: host:port）
	Reconnect  bool   `json:"reconnect,omitempty"`          // 是否自动重连（tcp_client类型，默认false）
}

// FrameResponse 帧响应DTO
type FrameResponse struct {
	Success   bool      `json:"success"`   // 是否成功
	Message   string    `json:"message"`   // 消息
	HexData   string    `json:"hexData"`   // 十六进制数据
	Frame     *FrameDTO `json:"frame"`     // 解析后的帧信息
	Timestamp time.Time `json:"timestamp"` // 时间戳
}

// FrameDTO 帧信息DTO
type FrameDTO struct {
	Prefix   byte   `json:"prefix"`   // 帧起始符
	Type     byte   `json:"type"`     // 表计类型
	TypeName string `json:"typeName"` // 表计类型名称
	Addr     string `json:"addr"`     // 地址
	Control  byte   `json:"control"`  // 控制码
	CtrlName string `json:"ctrlName"` // 控制码名称
	Len      int    `json:"len"`      // 数据域长度
	DataID   string `json:"dataId"`   // 数据标识（十六进制字符串）
	Serial   byte   `json:"serial"`   // 序列号
	Checksum byte   `json:"checksum"` // 校验和
	// 应答帧专用字段
	FlowData      uint32 `json:"flowData,omitempty"`      // 累积流量值
	FlowDataHex   string `json:"flowDataHex,omitempty"`   // 累积流量（十六进制）
	ValveStatus   int    `json:"valveStatus,omitempty"`   // 阀门状态：0-开阀，1-关阀，2-异常，3-未知
	BatteryStatus bool   `json:"batteryStatus,omitempty"` // 电池状态：false-正常，true-欠压
	IT05Status    bool   `json:"it05Status,omitempty"`    // IT05状态：false-正常，true-异常
	AlarmStatus   int    `json:"alarmStatus,omitempty"`   // 报警器状态
	Status        byte   `json:"status,omitempty"`        // 状态字节
	Timestamp     string `json:"timestamp"`               // 时间戳字符串
}

// ToFrameDTO 将 Cj188Frame 转换为 FrameDTO
func ToFrameDTO(frame *cj188.Cj188Frame) *FrameDTO {
	dto := &FrameDTO{
		Prefix:    frame.Prefix,
		Type:      frame.Type,
		TypeName:  getMeterTypeName(frame.Type),
		Addr:      frame.Addr,
		Control:   frame.Control,
		CtrlName:  getControlName(frame.Control),
		Len:       frame.Len,
		Serial:    frame.Serial,
		Checksum:  frame.Checksum,
		Timestamp: frame.Timestamp.Format("2006-01-02 15:04:05"),
	}

	// 数据标识转换为十六进制字符串
	if len(frame.DataID) == 2 {
		dto.DataID = fmt.Sprintf("%02X%02X", frame.DataID[0], frame.DataID[1])
	}

	// 应答帧的额外信息
	if frame.Control == cj188.CTRL_REPLY {
		dto.FlowData = frame.GetFlowData()
		dto.FlowDataHex = fmt.Sprintf("0x%08X", dto.FlowData)
		dto.ValveStatus = frame.GetValveStatus()
		dto.BatteryStatus = frame.GetBatteryStatus()
		dto.IT05Status = frame.GetIT05Status()
		dto.AlarmStatus = frame.GetAlarmStatus()
		dto.Status = frame.Status
	}

	return dto
}

// getMeterTypeName 获取表计类型名称
func getMeterTypeName(meterType byte) string {
	switch int(meterType) {
	case cj188.TYPE_WATER:
		return "水表"
	case cj188.TYPE_GAS:
		return "气表"
	case cj188.TYPE_ELECTRICITY:
		return "电表"
	default:
		return "未知"
	}
}

// getControlName 获取控制码名称
func getControlName(control byte) string {
	switch control {
	case cj188.CTRL_READ:
		return "读数据"
	case cj188.CTRL_REPLY:
		return "数据应答"
	case cj188.CTRL_CLOSE_VALVE:
		return "关阀指令"
	case cj188.CTRL_OPEN_VALVE:
		return "开阀指令"
	case cj188.CTRL_SET_PARAM:
		return "设置参数指令"
	case cj188.CTRL_REPLY_CLOSE:
		return "关阀应答"
	case cj188.CTRL_REPLY_OPEN:
		return "开阀应答"
	case cj188.CTRL_REPLY_SET_PARAM:
		return "设置参数应答"
	default:
		return fmt.Sprintf("未知 (0x%02X)", control)
	}
}
