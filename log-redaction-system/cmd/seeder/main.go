package main

import (
	"fmt"
	"time"

	"log-redaction-system/database"
	"log-redaction-system/masker"
)

func main() {
	// 1. Kết nối Database (Dùng chung cấu hình với app chính)
	database.ConnectDB()

	fmt.Println("⏳ Đang chuẩn bị dữ liệu và MÃ HÓA AES 10.000 dòng...")
	start := time.Now()

	// 2. Mở một Giao dịch (Transaction)
	// Việc dùng Transaction giúp đẩy 10.000 dòng cùng 1 lúc, tốc độ sẽ nhanh gấp hàng trăm lần so với đẩy từng dòng.
	tx, err := database.DB.Begin()
	if err != nil {
		panic("Lỗi mở Transaction: " + err.Error())
	}

	// Chuẩn bị câu lệnh SQL
	stmt, err := tx.Prepare("INSERT INTO system_logs_aes (service_name, ip_address, api_token, message) VALUES (?, ?, ?, ?)")
	if err != nil {
		panic("Lỗi Prepare SQL: " + err.Error())
	}
	defer stmt.Close()

	// Danh sách các Service giả định
	services := []string{"AuthService", "PaymentAPI", "UserService", "OrderService"}

	// 3. Vòng lặp bơm 10.000 dòng
	for i := 1; i <= 10000; i++ {
		// Tạo dữ liệu ngẫu nhiên có quy luật
		svc := services[i%4]
		rawIP := fmt.Sprintf("192.168.%d.%d", (i/255)%255, i%255)
		rawToken := fmt.Sprintf("sk_live_token_bulk_%d", i)
		msg := fmt.Sprintf("Bản ghi tự động sinh số %d phục vụ Load Test", i)

		// MÃ HÓA NGAY TRÊN RAM
		encIP := masker.MaskIP(rawIP)
		encToken := masker.MaskToken(rawToken)

		// Đưa vào hàng đợi của SQL
		_, err = stmt.Exec(svc, encIP, encToken, msg)
		if err != nil {
			fmt.Printf("⚠️ Lỗi insert dòng %d: %v\n", i, err)
		}
	}

	// 4. Chốt giao dịch (Đẩy toàn bộ xuống ổ cứng)
	err = tx.Commit()
	if err != nil {
		panic("Lỗi Commit: " + err.Error())
	}

	elapsed := time.Since(start)
	fmt.Printf("✅ BÙM! Đã bơm thành công 10.000 dòng dữ liệu MÃ HÓA AES vào database.\n")
	fmt.Printf("⏱️ Tổng thời gian xử lý: %s\n", elapsed)
}
