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
