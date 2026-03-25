package masker

// Khai báo một Khóa bí mật (Secret Key) 16 ký tự dùng chung cho toàn hệ thống
// Bạn có thể đổi khóa này thành bất kỳ chuỗi nào dài đúng 16 ký tự
const SecretKey = "LogMaskingKey123"

// MaskIP che giấu IP bằng thuật toán mã hóa AES-128
func MaskIP(ip string) string {
	// Gọi sang hàm mã hóa AES ở file aes.go
	return MaskDataWithAES(ip, SecretKey)
}

// MaskToken che giấu Token bằng thuật toán mã hóa AES-128
func MaskToken(token string) string {
	return MaskDataWithAES(token, SecretKey)
}

// package masker

// // IP
// func MaskIP(ip string) string {
// 	// Chuyển chuỗi thành mảng ký tự
// 	runes := []rune(ip)
// 	length := len(runes)

// 	// Tạo mảng mới chứa kết quả
// 	result := make([]rune, length)

// 	dotCount := 0

// 	for i := 0; i < length; i++ {
// 		if runes[i] == '.' {
// 			dotCount++
// 			result[i] = '.'
// 		} else if dotCount >= 2 {
// 			result[i] = '*'
// 		} else {
// 			result[i] = runes[i]
// 		}
// 	}

// 	return string(result) // rune -> string
// }

// // API Token
// func MaskToken(token string) string {
// 	runes := []rune(token)
// 	length := len(runes)

// 	if length <= 10 {
// 		return token
// 	}

// 	result := make([]rune, length)
// 	for i := 0; i < length; i++ {
// 		if i >= 6 && i < length-4 {
// 			result[i] = '*'
// 		} else {
// 			result[i] = runes[i]
// 		}
// 	}

// 	return string(result)
// }
