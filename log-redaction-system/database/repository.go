package database

import (
	"fmt"
	"log"
	"time"

	"log-redaction-system/masker"
	"log-redaction-system/models"
)

// ==========================================
// 1. LUỒNG POST: NHẬN LOG TỪ MICROSERVICE VÀ LƯU MÃ HÓA
// ==========================================
func SaveLog(logItem models.SystemLog) error {
	start := time.Now()

	// 1. Mã hóa dữ liệu ngay trên RAM (Encryption at Rest) bằng AES
	encIP := masker.MaskIP(logItem.IPAddress)
	encToken := masker.MaskToken(logItem.APIToken)

	// 2. Lưu chuỗi đã mã hóa vào bảng chuyên dụng AES
	query := "INSERT INTO system_logs_aes (service_name, ip_address, api_token, message) VALUES (?, ?, ?, ?)"
	_, err := DB.Exec(query, logItem.ServiceName, encIP, encToken, logItem.Message)

	if err == nil {
		fmt.Printf("📥 Đã nhận, mã hóa AES và lưu 1 log từ Microservice (Mất %v)\n", time.Since(start))
	} else {
		log.Printf("[-] Lỗi khi lưu vào DB: %v\n", err)
	}

	return err
}

// ==========================================
// 2. LUỒNG GET: ĐỌC DỮ LIỆU TỪ KÉT VÀ GIẢI MÃ CHO ADMIN
// ==========================================
func GetAndDecryptLogs() []models.SystemLog {
	start := time.Now()

	// 1. Lấy dữ liệu (đang ở dạng chuỗi Hex loằng ngoằng) từ bảng AES
	query := "SELECT id, timestamp, service_name, ip_address, api_token, message FROM system_logs_aes ORDER BY id DESC LIMIT 1000"
	rows, err := DB.Query(query)
	if err != nil {
		log.Fatalf("[-] Lỗi truy vấn dữ liệu: %v", err)
	}
	defer rows.Close()

	var logs []models.SystemLog

	for rows.Next() {
		var logItem models.SystemLog

		err := rows.Scan(&logItem.ID, &logItem.Timestamp, &logItem.ServiceName, &logItem.IPAddress, &logItem.APIToken, &logItem.Message)
		if err != nil {
			log.Printf("[-] Lỗi đọc dòng dữ liệu: %v", err)
			continue
		}

		// 2. GIẢI MÃ: Biến chuỗi Hex trở lại thành IP và Token thật
		logItem.IPAddress = masker.DecryptIP(logItem.IPAddress)
		logItem.APIToken = masker.DecryptToken(logItem.APIToken)

		logs = append(logs, logItem)
	}

	elapsed := time.Since(start)
	fmt.Printf("\n[+] Thời gian kéo và GIẢI MÃ %d dòng Log từ bảng AES: %s\n", len(logs), elapsed)

	return logs
}
