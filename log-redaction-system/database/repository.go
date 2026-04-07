package database

import (
	"fmt"
	"log"
	"os"
	"time"

	"log-redaction-system/masker"
	"log-redaction-system/models"
)

// getMasterKey lấy khóa chủ từ file .env
func getMasterKey() string {
	key := os.Getenv("MASTER_KEY")
	if key == "" {
		return "ACT_Tung_Nguyen_Secret_Key_2026" // Fallback an toàn
	}
	return key
}

// ==========================================
// 1. LUỒNG POST: NHẬN LOG VÀ LƯU MÃ HÓA (KDF)
// ==========================================
func SaveLog(logItem models.SystemLog) error {
	start := time.Now()
	masterKey := getMasterKey()

	// 1. Sinh SALT ngẫu nhiên cho riêng dòng log này
	salt := masker.GenerateSalt()

	// 2. Mã hóa bằng Khóa Phái Sinh (Truyền MasterKey và Salt)
	encIP := masker.MaskIP(logItem.IPAddress, masterKey, salt)
	encToken := masker.MaskToken(logItem.APIToken, masterKey, salt)

	// 3. Lưu vào Database (Nhớ lưu cả SALT để sau này còn giải mã)
	query := "INSERT INTO system_logs_aes (service_name, ip_address, api_token, salt, message) VALUES (?, ?, ?, ?, ?)"
	_, err := DB.Exec(query, logItem.ServiceName, encIP, encToken, salt, logItem.Message)

	if err == nil {
		fmt.Printf("📥 Đã nhận và mã hóa AES (KDF) 1 log (Mất %v)\n", time.Since(start))
	} else {
		log.Printf("[-] Lỗi khi lưu vào DB: %v\n", err)
	}

	return err
}

// ==========================================
// 2. LUỒNG GET: ĐỌC VÀ GIẢI MÃ CHO ADMIN
// ==========================================
func GetAndDecryptLogs() []models.SystemLog {
	start := time.Now()
	masterKey := getMasterKey()

	// Lấy thêm cột 'salt' từ DB
	query := "SELECT id, timestamp, service_name, ip_address, api_token, salt, message FROM system_logs_aes ORDER BY id DESC LIMIT 1000"
	rows, err := DB.Query(query)
	if err != nil {
		log.Fatalf("[-] Lỗi truy vấn dữ liệu: %v", err)
	}
	defer rows.Close()

	var logs []models.SystemLog
	for rows.Next() {
		var logItem models.SystemLog

		// Quét thêm giá trị vào logItem.Salt
		err := rows.Scan(&logItem.ID, &logItem.Timestamp, &logItem.ServiceName, &logItem.IPAddress, &logItem.APIToken, &logItem.Salt, &logItem.Message)
		if err != nil {
			log.Printf("[-] Lỗi đọc dòng dữ liệu: %v", err)
			continue
		}

		// GIẢI MÃ: Đưa IP, Token, MasterKey và đúng cái Salt của dòng đó vào máy giải mã
		logItem.IPAddress = masker.DecryptIP(logItem.IPAddress, masterKey, logItem.Salt)
		logItem.APIToken = masker.DecryptToken(logItem.APIToken, masterKey, logItem.Salt)

		logs = append(logs, logItem)
	}

	fmt.Printf("\n[+] Thời gian kéo và GIẢI MÃ %d dòng: %s\n", len(logs), time.Since(start))
	return logs
}

// ==========================================
// 3. API EXTRA 1: Lấy thô từ DB và Mask *** (Không giải mã)
// ==========================================
func GetRawAndStaticMaskLogs() []models.SystemLog {
	start := time.Now()
	// Không cần giải mã nên không kéo cột Salt
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

// ==========================================
// 4. API EXTRA 2: Lấy thô, GIẢI MÃ AES, rồi mới Mask ***
// ==========================================
func GetDecryptAndStaticMaskLogs() []models.SystemLog {
	start := time.Now()
	masterKey := getMasterKey()

	// Kéo thêm cột Salt
	query := "SELECT id, timestamp, service_name, ip_address, api_token, salt, message FROM system_logs_aes ORDER BY id DESC LIMIT 1000"
	rows, _ := DB.Query(query)
	defer rows.Close()

	var logs []models.SystemLog
	for rows.Next() {
		var logItem models.SystemLog
		rows.Scan(&logItem.ID, &logItem.Timestamp, &logItem.ServiceName, &logItem.IPAddress, &logItem.APIToken, &logItem.Salt, &logItem.Message)

		// Giải mã ra chữ thật trước
		realIP := masker.DecryptIP(logItem.IPAddress, masterKey, logItem.Salt)
		realToken := masker.DecryptToken(logItem.APIToken, masterKey, logItem.Salt)

		// Đè thuật toán Masking lên chữ thật
		logItem.IPAddress = masker.StaticMaskIP(realIP)
		logItem.APIToken = masker.StaticMaskToken(realToken)

		logs = append(logs, logItem)
	}
	fmt.Printf("\n[+] Thời gian API 2 (Giải mã + Mask ***): %s\n", time.Since(start))
	return logs
}

// ==========================================
// 5. API EXTRA 3: Giải mã và Mask NGẪU NHIÊN (Random)
// ==========================================
func GetRandomMaskLogs() []models.SystemLog {
	start := time.Now()
	masterKey := getMasterKey()

	query := "SELECT id, timestamp, service_name, ip_address, api_token, salt, message FROM system_logs_aes ORDER BY id DESC LIMIT 1000"
	rows, _ := DB.Query(query)
	defer rows.Close()

	var logs []models.SystemLog
	for rows.Next() {
		var logItem models.SystemLog
		rows.Scan(&logItem.ID, &logItem.Timestamp, &logItem.ServiceName, &logItem.IPAddress, &logItem.APIToken, &logItem.Salt, &logItem.Message)

		logItem.IPAddress = masker.RandomMaskData(masker.DecryptIP(logItem.IPAddress, masterKey, logItem.Salt))
		logItem.APIToken = masker.RandomMaskData(masker.DecryptToken(logItem.APIToken, masterKey, logItem.Salt))

		logs = append(logs, logItem)
	}
	fmt.Printf("\n[+] Thời gian API 3 (Giải mã + Random Mask): %s\n", time.Since(start))
	return logs
}

// ==========================================
// 6. API EXTRA 4: Giải mã và Mask CHÈN (Insert)
// ==========================================
func GetInsertMaskLogs() []models.SystemLog {
	start := time.Now()
	masterKey := getMasterKey()

	query := "SELECT id, timestamp, service_name, ip_address, api_token, salt, message FROM system_logs_aes ORDER BY id DESC LIMIT 1000"
	rows, _ := DB.Query(query)
	defer rows.Close()

	var logs []models.SystemLog
	for rows.Next() {
		var logItem models.SystemLog
		rows.Scan(&logItem.ID, &logItem.Timestamp, &logItem.ServiceName, &logItem.IPAddress, &logItem.APIToken, &logItem.Salt, &logItem.Message)

		logItem.IPAddress = masker.InsertMaskData(masker.DecryptIP(logItem.IPAddress, masterKey, logItem.Salt))
		logItem.APIToken = masker.InsertMaskData(masker.DecryptToken(logItem.APIToken, masterKey, logItem.Salt))

		logs = append(logs, logItem)
	}
	fmt.Printf("\n[+] Thời gian API 4 (Giải mã + Insert Mask): %s\n", time.Since(start))
	return logs
}
