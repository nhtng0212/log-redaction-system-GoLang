package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"log-redaction-system/database"
	"log-redaction-system/models"
)

// LogsHandler là trạm trung chuyển kiểm tra xem client đang gửi POST (Ghi) hay GET (Đọc)
func LogsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// ==========================================
	// KỊCH BẢN 1: CÁC MICROSERVICE BẮN LOG TỚI (POST)
	// ==========================================
	if r.Method == http.MethodPost {
		var incomingLog models.SystemLog

		// Đọc cục JSON từ request đập vào Struct của Go
		err := json.NewDecoder(r.Body).Decode(&incomingLog)
		if err != nil {
			http.Error(w, `{"error": "Dữ liệu JSON không hợp lệ"}`, http.StatusBadRequest)
			return
		}

		// Gọi hàm mã hóa và lưu vào Database
		err = database.SaveLog(incomingLog)
		if err != nil {
			http.Error(w, `{"error": "Lỗi khi lưu vào Database"}`, http.StatusInternalServerError)
			return
		}

		// Trả về mã 201 Created báo hiệu đã tạo thành công
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"message": "Log đã được mã hóa AES và lưu trữ an toàn!"}`))
		return
	}

	// ==========================================
	// KỊCH BẢN 2: QUẢN TRỊ VIÊN ĐỌC LOG (GET)
	// ==========================================
	if r.Method == http.MethodGet {
		// Gọi hàm lấy dữ liệu từ DB lên và GIẢI MÃ
		decryptedLogs := database.GetAndDecryptLogs()

		// Đóng gói thành JSON trả về cho Admin
		jsonResult, _ := json.MarshalIndent(decryptedLogs, "", "  ")
		w.Write(jsonResult)
		return
	}

	// Chặn các method khác (như PUT, DELETE)
	http.Error(w, `{"error": "Method không được hỗ trợ"}`, http.StatusMethodNotAllowed)
}

func StartServer() {
	http.HandleFunc("/api/logs", LogsHandler)

	fmt.Println("🌐 Centralized Log Server đang chạy tại: http://localhost:8080")
	fmt.Println("👉 Đọc Log (GET)   : http://localhost:8080/api/logs")
	fmt.Println("👉 Ghi Log (POST)  : http://localhost:8080/api/logs")

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Printf("❌ Lỗi khởi động Server: %v\n", err)
	}
}
