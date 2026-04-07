package main

import (
	"fmt"
	"os"
	"time"

	"log-redaction-system/database"
	"log-redaction-system/masker"
)

func main() {
	// 1. Kết nối Database (sẽ tự động load file .env nhờ cấu hình mới)
	database.ConnectDB()

	fmt.Println("⏳ Đang chuẩn bị dữ liệu và MÃ HÓA AES (KDF) 10.000 dòng...")
	start := time.Now()

	tx, err := database.DB.Begin()
	if err != nil {
		panic("Lỗi mở Transaction: " + err.Error())
	}

	// ĐÃ NÂNG CẤP: Thêm trường salt vào câu lệnh INSERT
	stmt, err := tx.Prepare("INSERT INTO system_logs_aes (service_name, ip_address, api_token, salt, message) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		panic("Lỗi Prepare SQL: " + err.Error())
	}
	defer stmt.Close()

	services := []string{"AuthService", "PaymentAPI", "UserService", "OrderService"}

	// Lấy Khóa chủ (Master Key) 1 lần ngoài vòng lặp để tối ưu tốc độ
	masterKey := os.Getenv("MASTER_KEY")
	if masterKey == "" {
		masterKey = "ACT_Tung_Nguyen_Secret_Key_2026" // Fallback an toàn
	}

	// 3. Vòng lặp bơm 10.000 dòng
	for i := 1; i <= 10000; i++ {
		// Dữ liệu giả định
		svc := services[i%4]
		// Để dễ test tính đa hình, tôi cố tình để IP lặp lại (cứ 255 dòng lại quay về IP cũ)
		rawIP := fmt.Sprintf("192.168.1.%d", i%255)
		rawToken := fmt.Sprintf("sk_live_token_bulk_%d", i)
		msg := fmt.Sprintf("Bản ghi tự động sinh số %d phục vụ Load Test", i)

		// BƯỚC QUAN TRỌNG: Sinh Salt ngẫu nhiên cho dòng log này
		salt := masker.GenerateSalt()

		// MÃ HÓA VỚI MASTER KEY VÀ SALT
		encIP := masker.MaskIP(rawIP, masterKey, salt)
		encToken := masker.MaskToken(rawToken, masterKey, salt)

		// Đưa vào hàng đợi của SQL (Nhớ lưu cả chuỗi Salt xuống DB)
		_, err = stmt.Exec(svc, encIP, encToken, salt, msg)
		if err != nil {
			fmt.Printf("⚠️ Lỗi insert dòng %d: %v\n", i, err)
		}
	}

	// 4. Chốt giao dịch (Đẩy toàn bộ 10.000 dòng xuống ổ cứng trong 1 nhịp)
	err = tx.Commit()
	if err != nil {
		panic("Lỗi Commit: " + err.Error())
	}

	elapsed := time.Since(start)
	fmt.Printf("✅ BÙM! Đã bơm thành công 10.000 dòng dữ liệu MÃ HÓA AES (KDF) vào database.\n")
	fmt.Printf("⏱️ Tổng thời gian xử lý: %s\n", elapsed)
}
