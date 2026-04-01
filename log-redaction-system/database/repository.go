// Package database xu ly luu tru va truy xuat log da ma hoa.
package database

import (
	"fmt"
	"log"
	"time"

	"log-redaction-system/masker"
	"log-redaction-system/models"
)

// SaveLog ma hoa IP va token roi luu vao bang system_logs_aes.
func SaveLog(logItem models.SystemLog) error {
	start := time.Now()
	encIP := masker.MaskIP(logItem.IPAddress)
	encToken := masker.MaskToken(logItem.APIToken)
	query := "INSERT INTO system_logs_aes (service_name, ip_address, api_token, message) VALUES (?, ?, ?, ?)"
	_, err := DB.Exec(query, logItem.ServiceName, encIP, encToken, logItem.Message)

	if err == nil {
		fmt.Printf("📥 Đã nhận, mã hóa AES và lưu 1 log từ Microservice (Mất %v)\n", time.Since(start))
	} else {
		log.Printf("[-] Lỗi khi lưu vào DB: %v\n", err)
	}

	return err
}

// GetAndDecryptLogs doc log tu DB va giai ma IP/token cho admin.
func GetAndDecryptLogs() []models.SystemLog {
	start := time.Now()
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
		logItem.IPAddress = masker.DecryptIP(logItem.IPAddress)
		logItem.APIToken = masker.DecryptToken(logItem.APIToken)

		logs = append(logs, logItem)
	}

	elapsed := time.Since(start)
	fmt.Printf("\n[+] Thời gian kéo và GIẢI MÃ %d dòng Log từ bảng AES: %s\n", len(logs), elapsed)

	return logs
}

// GetRawAndStaticMaskLogs lay du lieu AES tho va mask tinh truc tiep.
func GetRawAndStaticMaskLogs() []models.SystemLog {
	start := time.Now()
	query := "SELECT id, timestamp, service_name, ip_address, api_token, message FROM system_logs_aes ORDER BY id DESC LIMIT 1000"
	rows, _ := DB.Query(query)
	defer rows.Close()

	var logs []models.SystemLog
	for rows.Next() {
		var logItem models.SystemLog
		rows.Scan(&logItem.ID, &logItem.Timestamp, &logItem.ServiceName, &logItem.IPAddress, &logItem.APIToken, &logItem.Message)
		logItem.IPAddress = masker.StaticMaskIP(logItem.IPAddress)
		logItem.APIToken = masker.StaticMaskToken(logItem.APIToken)

		logs = append(logs, logItem)
	}
	fmt.Printf("\n[+] Thời gian API 1 (Lấy thô + Mask ***): %s\n", time.Since(start))
	return logs
}

// GetDecryptAndStaticMaskLogs giai ma du lieu AES roi mask tinh.
func GetDecryptAndStaticMaskLogs() []models.SystemLog {
	start := time.Now()
	query := "SELECT id, timestamp, service_name, ip_address, api_token, message FROM system_logs_aes ORDER BY id DESC LIMIT 1000"
	rows, _ := DB.Query(query)
	defer rows.Close()

	var logs []models.SystemLog
	for rows.Next() {
		var logItem models.SystemLog
		rows.Scan(&logItem.ID, &logItem.Timestamp, &logItem.ServiceName, &logItem.IPAddress, &logItem.APIToken, &logItem.Message)
		realIP := masker.DecryptIP(logItem.IPAddress)
		realToken := masker.DecryptToken(logItem.APIToken)
		logItem.IPAddress = masker.StaticMaskIP(realIP)
		logItem.APIToken = masker.StaticMaskToken(realToken)

		logs = append(logs, logItem)
	}
	fmt.Printf("\n[+] Thời gian API 2 (Giải mã + Mask ***): %s\n", time.Since(start))
	return logs
}

// GetRandomMaskLogs giai ma du lieu AES roi mask ngau nhien.
func GetRandomMaskLogs() []models.SystemLog {
	start := time.Now()
	query := "SELECT id, timestamp, service_name, ip_address, api_token, message FROM system_logs_aes ORDER BY id DESC LIMIT 1000"
	rows, _ := DB.Query(query)
	defer rows.Close()

	var logs []models.SystemLog
	for rows.Next() {
		var logItem models.SystemLog
		rows.Scan(&logItem.ID, &logItem.Timestamp, &logItem.ServiceName, &logItem.IPAddress, &logItem.APIToken, &logItem.Message)
		logItem.IPAddress = masker.RandomMaskData(masker.DecryptIP(logItem.IPAddress))
		logItem.APIToken = masker.RandomMaskToken(masker.DecryptToken(logItem.APIToken))

		logs = append(logs, logItem)
	}
	fmt.Printf("\n[+] Thời gian API 3 (Giải mã + Random Mask): %s\n", time.Since(start))
	return logs
}

// GetInsertMaskLogs giai ma du lieu AES roi mask chen nhan.
func GetInsertMaskLogs() []models.SystemLog {
	start := time.Now()
	query := "SELECT id, timestamp, service_name, ip_address, api_token, message FROM system_logs_aes ORDER BY id DESC LIMIT 1000"
	rows, _ := DB.Query(query)
	defer rows.Close()

	var logs []models.SystemLog
	for rows.Next() {
		var logItem models.SystemLog
		rows.Scan(&logItem.ID, &logItem.Timestamp, &logItem.ServiceName, &logItem.IPAddress, &logItem.APIToken, &logItem.Message)
		logItem.IPAddress = masker.InsertMaskData(masker.DecryptIP(logItem.IPAddress))
		logItem.APIToken = masker.InsertMaskToken(masker.DecryptToken(logItem.APIToken))

		logs = append(logs, logItem)
	}
	fmt.Printf("\n[+] Thời gian API 4 (Giải mã + Insert Mask): %s\n", time.Since(start))
	return logs
}

// GetShuffleMaskLogs giai ma du lieu AES roi xao tron ky tu du lieu.
func GetShuffleMaskLogs() []models.SystemLog {
	start := time.Now()
	query := "SELECT id, timestamp, service_name, ip_address, api_token, message FROM system_logs_aes ORDER BY id DESC LIMIT 1000"
	rows, _ := DB.Query(query)
	defer rows.Close()

	var logs []models.SystemLog
	for rows.Next() {
		var logItem models.SystemLog
		rows.Scan(&logItem.ID, &logItem.Timestamp, &logItem.ServiceName, &logItem.IPAddress, &logItem.APIToken, &logItem.Message)
		logItem.IPAddress = masker.ShuffleMaskData(masker.DecryptIP(logItem.IPAddress))
		logItem.APIToken = masker.ShuffleMaskToken(masker.DecryptToken(logItem.APIToken))

		logs = append(logs, logItem)
	}
	fmt.Printf("\n[+] Thời gian API 5 (Giải mã + Shuffle Mask): %s\n", time.Since(start))
	return logs
}
