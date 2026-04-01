// Package main tao du lieu mau da ma hoa de seed database.
package main

import (
	"fmt"
	"time"

	"log-redaction-system/database"
	"log-redaction-system/masker"
)

// main sinh log mau va chen vao bang system_logs_aes.
func main() {
	database.ConnectDB()

	fmt.Println("⏳ Đang chuẩn bị dữ liệu và MÃ HÓA AES 10.000 dòng...")
	start := time.Now()

	tx, err := database.DB.Begin()
	if err != nil {
		panic("Lỗi mở Transaction: " + err.Error())
	}
	stmt, err := tx.Prepare("INSERT INTO system_logs_aes (service_name, ip_address, api_token, message) VALUES (?, ?, ?, ?)")
	if err != nil {
		panic("Lỗi Prepare SQL: " + err.Error())
	}
	defer stmt.Close()
	services := []string{"AuthService", "PaymentAPI", "UserService", "OrderService"}
	for i := 1; i <= 10000; i++ {
		svc := services[i%4]
		rawIP := fmt.Sprintf("192.168.%d.%d", (i/255)%255, i%255)
		rawToken := fmt.Sprintf("sk_live_token_bulk_%d", i)
		msg := fmt.Sprintf("Bản ghi tự động sinh số %d phục vụ Load Test", i)
		encIP := masker.MaskIP(rawIP)
		encToken := masker.MaskToken(rawToken)
		_, err = stmt.Exec(svc, encIP, encToken, msg)
		if err != nil {
			fmt.Printf("⚠️ Lỗi insert dòng %d: %v\n", i, err)
		}
	}
	err = tx.Commit()
	if err != nil {
		panic("Lỗi Commit: " + err.Error())
	}

	elapsed := time.Since(start)
	fmt.Printf("✅ BÙM! Đã bơm thành công 10.000 dòng dữ liệu MÃ HÓA AES vào database.\n")
	fmt.Printf("⏱️ Tổng thời gian xử lý: %s\n", elapsed)
}
