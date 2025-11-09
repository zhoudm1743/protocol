package utils

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

var HexTool = hexTool{}

type hexTool struct{}

const hextable = "0123456789ABCDEF"

// Join 将两个字节数组连接起来
func (h hexTool) Join(src []byte, dst []byte) []byte {
	var ret []byte = make([]byte, len(src))
	copy(ret, src)
	ret = append(ret, dst...)
	return ret
}

// CheckSum 计算校验和
func (h hexTool) CheckSum(data []byte) byte {
	var sum byte = 0
	for _, v := range data {
		sum += v
	}
	return sum
}

// ClearFE 清除字节数组中的FE
func (h hexTool) ClearFE(data []byte) []byte {
	ret := data
	prefix := []byte{0xFE}
	for {
		if bytes.HasPrefix(ret, prefix) {
			ret = ret[1:]
		} else {
			break
		}
	}

	return ret
}

// CRC16 计算CRC16校验和
func (h hexTool) CRC16(data []byte) []byte {
	var crc_reg, crc_gen uint32
	crc_reg, crc_gen = 0xFFFF, 0xA001

	for i, l := 0, len(data); i < l; i++ {
		crc_reg = (uint32(data[i]) & 0xff) ^ crc_reg
		for j := 8; j > 0; j-- {
			if crc_reg&0x01 == 1 {
				crc_reg >>= 1
				crc_reg ^= crc_gen
			} else {
				crc_reg >>= 1
			}
		}
	}

	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(crc_reg))
	return buf
}

// BytesReverse 字节数组反转
func (h hexTool) BytesReverse(data []byte) []byte {
	ret := make([]byte, len(data))
	copy(ret, data)
	for i, j := 0, len(ret)-1; i < j; i, j = i+1, j-1 {
		ret[i], ret[j] = ret[j], ret[i]
	}
	return ret
}

// ToHexString 将字节数组转换为十六进制字符串
func (h hexTool) ToHexString(data []byte) string {
	ret := make([]byte, len(data)*2)
	for i, v := range data {
		ret[i*2] = hextable[v>>4]
		ret[i*2+1] = hextable[v&0x0F]
	}
	return string(ret)
}

// hexCharToValue 将十六进制字符转换为数值
func hexCharToValue(c byte) byte {
	if c >= '0' && c <= '9' {
		return c - '0'
	}
	if c >= 'A' && c <= 'F' {
		return c - 'A' + 10
	}
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 10
	}
	return 0
}

// ToBytes 将十六进制字符串转换为字节数组
func (h hexTool) ToBytes(data string) []byte {
	ret := make([]byte, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			ret[i/2] = (hexCharToValue(data[i]) << 4) | hexCharToValue(data[i+1])
		}
	}
	return ret
}

// BCDToDecimal 将BCD码字节数组转换为十进制字符串（反向读取）
// 例如：[0x70, 0x48, 0x10, 0x23, 0x00, 0x00, 0x00] -> "23104870"
func (h hexTool) BCDToDecimal(bcdBytes []byte) string {
	if len(bcdBytes) == 0 {
		return ""
	}
	// 反向读取字节数组
	reversed := make([]byte, len(bcdBytes))
	for i := 0; i < len(bcdBytes); i++ {
		reversed[i] = bcdBytes[len(bcdBytes)-1-i]
	}
	// 将每个字节的BCD码转换为两位十进制数字
	var result []byte
	for _, b := range reversed {
		high := (b >> 4) & 0x0F
		low := b & 0x0F
		// 检查是否为有效的BCD码（0-9）
		if high <= 9 && low <= 9 {
			result = append(result, '0'+high, '0'+low)
		}
	}
	// 去除前导零
	str := string(result)
	for len(str) > 1 && str[0] == '0' {
		str = str[1:]
	}
	return str
}

// DecimalToBCD 将十进制字符串转换为BCD码字节数组（反向存储，7字节）
// 例如："23104870" -> [0x70, 0x48, 0x10, 0x23, 0x00, 0x00, 0x00]
func (h hexTool) DecimalToBCD(decimalStr string, byteLen int) ([]byte, error) {
	// 验证输入字符串只包含数字
	for _, c := range decimalStr {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("地址字符串包含非数字字符: %s", decimalStr)
		}
	}
	// 计算需要的数字位数（每个字节2位BCD码）
	requiredDigits := byteLen * 2
	// 如果数字位数不足，前面补0
	if len(decimalStr) < requiredDigits {
		decimalStr = strings.Repeat("0", requiredDigits-len(decimalStr)) + decimalStr
	} else if len(decimalStr) > requiredDigits {
		return nil, fmt.Errorf("地址字符串过长: 需要%d位数字，实际%d位", requiredDigits, len(decimalStr))
	}
	// 将字符串转换为BCD码字节数组（每两位数字一个字节）
	bcdBytes := make([]byte, byteLen)
	for i := 0; i < byteLen; i++ {
		high := decimalStr[i*2] - '0'
		low := decimalStr[i*2+1] - '0'
		bcdBytes[i] = (high << 4) | low
	}
	// 反向存储（小端序）
	reversed := make([]byte, byteLen)
	for i := 0; i < byteLen; i++ {
		reversed[i] = bcdBytes[byteLen-1-i]
	}
	return reversed, nil
}

// BCDToUint32 将BCD码字节数组转换为uint32值（按顺序解析，每个字节包含两位BCD码）
// 例如：[0x00, 0x02, 0x00, 0x00] -> 20000（BCD码：00 02 00 00 = 00020000）
// 解析方式：将每个字节的BCD码按顺序组合成字符串，然后转换为数值
func (h hexTool) BCDToUint32(bcdBytes []byte) uint32 {
	if len(bcdBytes) == 0 {
		return 0
	}
	// 将每个字节的BCD码转换为两位十进制数字字符串
	var bcdStr string
	for _, b := range bcdBytes {
		high := (b >> 4) & 0x0F
		low := b & 0x0F
		// 检查是否为有效的BCD码（0-9）
		if high <= 9 && low <= 9 {
			bcdStr += string('0' + high)
			bcdStr += string('0' + low)
		}
	}
	// 将BCD字符串转换为数值
	var result uint32
	for i := 0; i < len(bcdStr); i++ {
		result = result*10 + uint32(bcdStr[i]-'0')
	}
	return result
}
