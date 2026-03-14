package api

import (
	"encoding/json"
	"fmt"
	"log-redaction-system/database"
	"net/http"
)

// Xử lý khi người dùng gõ URL vào trình duyệt
func GetLogsHandler(w http.ResponseWriter, r *http.Request) {
	// Khai báo trình duyệt
	w.Header().Set("Content-Type", "application/json")

	// Lấy dữ liệu từ DB
	maskedLogs := database.GetAndMaskLogs()

	// Chuyển struct sang json
	jsonResult, err := json.MarshalIndent(maskedLogs, ""," ")
	if err != nil {
		http.Error(w, "Lỗi khi đóng gói JSON", http.StatusInternalServerError)
		return
	}

	w.Write(jsonResult)
}

// Khởi động Web Server ở cổng 8080
func StartServer() {
	// Định tuyến URL
	http.HandleFunc("/api/logs", GetLogsHandler)

	fmt.Println("🌐 Web Server đang chạy tại: http://localhost:8080")
	
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Print("[-] Lỗi khởi động Server: %v\n", err)
	}
}