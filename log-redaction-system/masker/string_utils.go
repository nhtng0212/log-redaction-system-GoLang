package masker

// IP
func MaskIP(ip string) string {
	// Chuyển chuỗi thành mảng ký tự
	runes := []rune(ip)
	length := len(runes)

	// Tạo mảng mới chứa kết quả
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

	return string(result) // rune -> string
}

// API Token
func MaskToken(token string) string {
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