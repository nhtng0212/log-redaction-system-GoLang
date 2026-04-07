package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"log-redaction-system/database"
	"log-redaction-system/models"

	"github.com/golang-jwt/jwt/v5"
)

// ==========================================
// 1. API: ĐĂNG NHẬP (CẤP TOKEN)
// ==========================================
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req models.LoginRequest
	json.NewDecoder(r.Body).Decode(&req)

	var user models.User
	query := "SELECT id, username, role FROM users WHERE username=? AND password=?"
	err := database.DB.QueryRow(query, req.Username, req.Password).Scan(&user.ID, &user.Username, &user.Role)

	if err != nil {
		http.Error(w, `{"error": "Sai tài khoản hoặc mật khẩu"}`, http.StatusUnauthorized)
		return
	}

	// Tạo thẻ JWT có thời hạn 24h
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "ACT_Tung_Nguyen_JWT_Secret_2026"
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(jwtSecret))

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString, "role": user.Role})
}

// ==========================================
// 2. API: BẮN LOG TỚI SERVER (POST)
// ==========================================
func CreateLogHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Chỉ hỗ trợ phương thức POST"}`, http.StatusMethodNotAllowed)
		return
	}

	var incomingLog models.SystemLog
	if err := json.NewDecoder(r.Body).Decode(&incomingLog); err != nil {
		http.Error(w, `{"error": "Dữ liệu JSON không hợp lệ"}`, http.StatusBadRequest)
		return
	}

	if err := database.SaveLog(incomingLog); err != nil {
		http.Error(w, `{"error": "Lỗi khi lưu vào Database"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"message": "Log đã được mã hóa AES-KDF và lưu trữ an toàn!"}`))
}

// ==========================================
// 3. CÁC API ĐỌC DỮ LIỆU (GET)
// ==========================================

func DecryptedLogsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	logs := database.GetAndDecryptLogs()
	json.NewEncoder(w).Encode(logs)
}

func StaticMaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	logs := database.GetDecryptAndStaticMaskLogs()
	json.NewEncoder(w).Encode(logs)
}

func RandomMaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	logs := database.GetRandomMaskLogs()
	json.NewEncoder(w).Encode(logs)
}

func InsertMaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	logs := database.GetInsertMaskLogs()
	json.NewEncoder(w).Encode(logs)
}

// ==========================================
// 4. KHỞI ĐỘNG SERVER VÀ ĐỊNH TUYẾN
// ==========================================
func StartServer() {
	http.Handle("/", http.FileServer(http.Dir("./web")))

	// API Đăng nhập không cần Token bảo vệ
	http.HandleFunc("/api/login", LoginHandler)

	// API Lưu Log
	http.HandleFunc("/api/logs", AuthMiddleware("dev", CreateLogHandler))

	// API Xem Chữ Thật: Cửa cực kỳ nghiêm ngặt, CHỈ ADMIN
	http.HandleFunc("/api/logs/decrypted", AuthMiddleware("admin", DecryptedLogsHandler))

	// API Xem Mask: Dev (và Admin) đều xem được
	http.HandleFunc("/api/logs/static-mask", AuthMiddleware("dev", StaticMaskHandler))
	http.HandleFunc("/api/logs/random-mask", AuthMiddleware("dev", RandomMaskHandler))
	http.HandleFunc("/api/logs/insert-mask", AuthMiddleware("dev", InsertMaskHandler))

	fmt.Println("=========================================================")
	fmt.Println("🛡️  SERVER BẢO MẬT AES-KDF & JWT ĐANG CHẠY TẠI PORT 8080")
	fmt.Println("=========================================================")
	fmt.Println("🌐 TRUY CẬP WEB TẠI : http://localhost:8080") // Dòng thông báo mới
	fmt.Println("=========================================================")

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Printf("❌ Lỗi khởi động Server: %v\n", err)
	}
}
