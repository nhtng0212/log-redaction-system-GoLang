package masker

// Khai báo Khóa bí mật (Secret Key) dùng chung cho toàn hệ thống
// Đã đưa về đúng 16 ký tự để chuẩn với AES-128
const SecretKey = "LogMaskingKey123"

// 1. NHÓM HÀM MÃ HÓA (DÙNG KHI LƯU VÀO DB)
// MaskIP che giấu IP bằng thuật toán mã hóa AES-128
func MaskIP(ip string) string {
	return MaskDataWithAES(ip, SecretKey)
}

// MaskToken che giấu Token bằng thuật toán mã hóa AES-128
func MaskToken(token string) string {
	return MaskDataWithAES(token, SecretKey)
}

// 2. NHÓM HÀM GIẢI MÃ (DÙNG KHI ĐỌC TỪ DB)
// DecryptIP giải mã IP từ chuỗi mã hóa Hex
func DecryptIP(encryptedIP string) string {
	return DecryptDataWithAES(encryptedIP, SecretKey)
}

// DecryptToken giải mã Token từ chuỗi mã hóa Hex
func DecryptToken(encryptedToken string) string {
	return DecryptDataWithAES(encryptedToken, SecretKey)
}

// 3. NHÓM HÀM STATIC MASKING (Che bằng dấu ***)
// StaticMaskIP che giấu IP theo kiểu cũ (Tìm dấu chấm và thay bằng *)
func StaticMaskIP(ip string) string {
	runes := []rune(ip)
	length := len(runes)

	// 1. Kiểm tra xem chuỗi có dấu chấm (IP thật) hay không
	hasDot := false
	for _, r := range runes {
		if r == '.' {
			hasDot = true
			break
		}
	}

	// 2. Nếu KHÔNG có dấu chấm (Đây là chuỗi Hex AES)
	// Ta sẽ giữ lại 6 ký tự đầu và 4 ký tự cuối, che toàn bộ khúc giữa
	if !hasDot {
		if length <= 10 {
			return ip
		}
		result := make([]rune, length)
		for i := 0; i < length; i++ {
			if i >= 6 && i < length-4 {
				result[i] = '*'
			} else {
				result[i] = runes[i]
			}
		}
		return string(result)
	}

	// 3. Nếu CÓ dấu chấm (Đây là IP thật)
	// Ta áp dụng luật cũ: che từ sau dấu chấm thứ 2
	result := make([]rune, length)
	dotCount := 0

	for i := 0; i < length; i++ {
		if runes[i] == '.' {
			dotCount++
			result[i] = '.'
		} else if dotCount >= 2 {
			result[i] = '*'
		} else {
			result[i] = runes[i]
		}
	}
	return string(result)
}

// StaticMaskToken che giấu Token (Giữ 6 đầu, 4 cuối)
func StaticMaskToken(token string) string {
	runes := []rune(token)
	length := len(runes)

	if length <= 10 {
		return token
	}

	result := make([]rune, length)
	for i := 0; i < length; i++ {
		if i >= 6 && i < length-4 {
			result[i] = '*'
		} else {
			result[i] = runes[i]
		}
	}
	return string(result)
}
