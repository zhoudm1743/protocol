package cj188

import (
	"testing"
)

// TestParser188_ReadFrame 测试解析查询帧
func TestParser188_ReadFrame(t *testing.T) {
	// 测试数据：FE FE FE 68 10 77 66 55 44 33 22 11 01 03 90 1F 01 08 16
	testData := []byte{
		0xFE, 0xFE, 0xFE, // 引导字符
		0x68,                                     // 帧起始符
		0x10,                                     // 表计类型（水表）
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // 地址
		0x01,       // 控制码（读数据）
		0x03,       // 数据域长度
		0x90, 0x1F, // 数据标识
		0x01, // 序列号
		0x08, // 校验和（需要验证）
		0x16, // 帧结束符
	}

	frame, err := Parser188(testData)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 验证帧头
	if frame.Type != byte(TYPE_WATER) {
		t.Errorf("表计类型错误: 期望0x%02X, 实际0x%02X", TYPE_WATER, frame.Type)
	}

	// 验证地址
	expectedAddr := "77665544332211"
	if frame.Addr != expectedAddr {
		t.Errorf("地址错误: 期望%s, 实际%s", expectedAddr, frame.Addr)
	}

	// 验证控制码
	if frame.Control != CTRL_READ {
		t.Errorf("控制码错误: 期望0x%02X, 实际0x%02X", CTRL_READ, frame.Control)
	}

	// 验证数据标识
	if len(frame.DataID) != 2 || frame.DataID[0] != 0x90 || frame.DataID[1] != 0x1F {
		t.Errorf("数据标识错误: 期望[0x90, 0x1F], 实际%v", frame.DataID)
	}

	// 验证序列号
	if frame.Serial != 0x01 {
		t.Errorf("序列号错误: 期望0x01, 实际0x%02X", frame.Serial)
	}
}

// TestParser188_ReplyFrame 测试解析应答帧
func TestParser188_ReplyFrame(t *testing.T) {
	// 测试数据：FE FE FE 68 10 77 66 55 44 33 22 11 81 09 90 1F 01 78 56 34 12 00 FF XX 16
	// 累积流量：0x12345678（小端序存储为 78 56 34 12）
	// 数据域从第11字节开始：数据标识(2) + 序列号(1) + 累积流量(4) + 状态0(1) + 状态1(1) = 9字节
	testData := []byte{
		0xFE, 0xFE, 0xFE, // 引导字符
		0x68,                                     // 帧起始符
		0x10,                                     // 表计类型（水表）
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // 地址
		0x81,       // 控制码（应答）
		0x09,       // 数据域长度（9字节：数据标识2 + 序列号1 + 累积流量4 + 状态0 1 + 状态1 1）
		0x90, 0x1F, // 数据标识（数据域开始）
		0x01,                   // 序列号
		0x78, 0x56, 0x34, 0x12, // 累积流量（小端序，实际值为0x12345678）
		0x00, // 状态0
		0xFF, // 状态1
		0x00, // 校验和（临时值，需要计算）
		0x16, // 帧结束符
	}
	// 计算校验和（从帧起始符到状态1，不包括校验和本身）
	// 帧结构：68(3) + 10(4) + 地址(5-11) + 81(12) + 09(13) + 数据域(14-22) + 校验和(23) + 16(24)
	// 校验和计算范围：从索引3(0x68)到索引22(0xFF)，不包括索引23(校验和)
	calcData := testData[3:23] // 跳过引导字符，从0x68到0xFF（不包括校验和）
	checksum := byte(0)
	for _, b := range calcData {
		checksum += b
	}
	testData[23] = checksum // 设置校验和（索引23）

	frame, err := Parser188(testData)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 验证控制码
	if frame.Control != CTRL_REPLY {
		t.Errorf("控制码错误: 期望0x%02X, 实际0x%02X", CTRL_REPLY, frame.Control)
	}

	// 验证数据域长度
	if frame.Len != 0x09 {
		t.Errorf("数据域长度错误: 期望0x09, 实际0x%02X", frame.Len)
	}

	// 验证累积流量
	expectedFlow := uint32(0x12345678)
	actualFlow := frame.GetFlowData()
	if actualFlow != expectedFlow {
		t.Errorf("累积流量错误: 期望0x%08X, 实际0x%08X", expectedFlow, actualFlow)
	}

	// 验证状态
	if frame.Status != 0x00 {
		t.Errorf("状态错误: 期望0x00, 实际0x%02X", frame.Status)
	}
}

// TestBuild188 测试构建查询帧
func TestBuild188(t *testing.T) {
	meterType := byte(TYPE_WATER)
	addr := "77665544332211"
	dataID := []byte{0x90, 0x1F}
	serial := byte(0x01)

	frame, err := Build188(meterType, addr, dataID, serial)
	if err != nil {
		t.Fatalf("构建失败: %v", err)
	}

	// 验证帧长度
	expectedLen := 16
	if len(frame) != expectedLen {
		t.Errorf("帧长度错误: 期望%d, 实际%d", expectedLen, len(frame))
	}

	// 验证帧起始符
	if frame[0] != FRAME_START {
		t.Errorf("帧起始符错误: 期望0x%02X, 实际0x%02X", FRAME_START, frame[0])
	}

	// 验证表计类型
	if frame[1] != meterType {
		t.Errorf("表计类型错误: 期望0x%02X, 实际0x%02X", meterType, frame[1])
	}

	// 验证控制码
	if frame[9] != CTRL_READ {
		t.Errorf("控制码错误: 期望0x%02X, 实际0x%02X", CTRL_READ, frame[9])
	}

	// 验证帧结束符
	if frame[len(frame)-1] != FRAME_END {
		t.Errorf("帧结束符错误: 期望0x%02X, 实际0x%02X", FRAME_END, frame[len(frame)-1])
	}

	// 验证可以解析回去
	parsedFrame, err := Parser188(frame)
	if err != nil {
		t.Fatalf("解析构建的帧失败: %v", err)
	}

	if parsedFrame.Addr != addr {
		t.Errorf("地址不匹配: 期望%s, 实际%s", addr, parsedFrame.Addr)
	}
}

// TestBuild188Reply 测试构建应答帧
func TestBuild188Reply(t *testing.T) {
	meterType := byte(TYPE_WATER)
	addr := "77665544332211"
	dataID := []byte{0x90, 0x1F}
	serial := byte(0x01)
	flowData := []byte{0x78, 0x56, 0x34, 0x12} // 累积流量0x12345678（小端序）
	status := byte(0x00)

	frame, err := Build188Reply(meterType, addr, dataID, serial, flowData, status)
	if err != nil {
		t.Fatalf("构建失败: %v", err)
	}

	// 验证帧长度（固定部分11字节 + 数据域9字节 + 校验和1字节 + 结束符1字节 = 22字节）
	expectedLen := 22
	if len(frame) != expectedLen {
		t.Errorf("帧长度错误: 期望%d, 实际%d", expectedLen, len(frame))
	}

	// 验证控制码
	if frame[9] != CTRL_REPLY {
		t.Errorf("控制码错误: 期望0x%02X, 实际0x%02X", CTRL_REPLY, frame[9])
	}

	// 验证可以解析回去
	parsedFrame, err := Parser188(frame)
	if err != nil {
		t.Fatalf("解析构建的帧失败: %v", err)
	}

	expectedFlow := uint32(0x12345678)
	actualFlow := parsedFrame.GetFlowData()
	if actualFlow != expectedFlow {
		t.Errorf("累积流量不匹配: 期望0x%08X, 实际0x%08X", expectedFlow, actualFlow)
	}
}

// TestParser188_InvalidFrame 测试无效帧
func TestParser188_InvalidFrame(t *testing.T) {
	// 测试帧长度不足
	shortData := []byte{0x68, 0x10}
	_, err := Parser188(shortData)
	if err == nil {
		t.Error("应该返回错误：帧长度不足")
	}

	// 测试无效的帧起始符
	invalidStart := []byte{0x69, 0x10, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x01, 0x03, 0x90, 0x1F, 0x01, 0x08, 0x16}
	_, err = Parser188(invalidStart)
	if err == nil {
		t.Error("应该返回错误：无效的帧起始符")
	}
}
