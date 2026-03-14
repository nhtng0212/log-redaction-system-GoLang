package database

import (
	"fmt"
	"log"
	"time"

	"log-redaction-system/masker"
	"log-redaction-system/models"
)

func GetAndMaskLogs() []models.SystemLog {
	start := time.Now()

	query := "SELECT id, timestamp, service_name, ip_address, api_token, message FROM system_logs"

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

		logItem.IPAddress = masker.MaskIP(logItem.IPAddress)
		logItem.APIToken = masker.MaskToken(logItem.APIToken)
		
		logs = append(logs, logItem)
	}

	elapsed := time.Since(start)
	fmt.Printf("\n[+] Thời gian truy vấn và che giấy %d dòng Log: %s\n", len(logs), elapsed)

	return logs
}