// Package api cung cap cac HTTP handler cho he thong log redaction.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"log-redaction-system/database"
	"log-redaction-system/models"
)

const (
	viewModePlain   = "plain"
	viewModeStatic  = "static"
	viewModeRandom  = "random"
	viewModeInsert  = "insert"
	viewModeShuffle = "shuffle"
)

func selectLogsByMode(mode string) []models.SystemLog {
	switch mode {
	case viewModePlain:
		return database.GetAndDecryptLogs()
	case viewModeStatic:
		return database.GetDecryptAndStaticMaskLogs()
	case viewModeRandom:
		return database.GetRandomMaskLogs()
	case viewModeInsert:
		return database.GetInsertMaskLogs()
	case viewModeShuffle:
		return database.GetShuffleMaskLogs()
	default:
		return database.GetDecryptAndStaticMaskLogs()
	}
}

func resolveModeForCaller(r *http.Request, requestedMode string) (string, error) {
	user := getAuthUser(r)
	if user == nil {
		return "", fmt.Errorf("unauthorized")
	}

	if user.Role == "admin" {
		return requestedMode, nil
	}

	devMode, err := database.GetDevViewMode()
	if err != nil {
		return "", err
	}
	return devMode, nil
}

func renderLogsByMode(w http.ResponseWriter, r *http.Request, requestedMode string) {
	mode, err := resolveModeForCaller(r, requestedMode)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Không thể xác định chế độ hiển thị"})
		return
	}

	logs := selectLogsByMode(mode)
	jsonResult, _ := json.MarshalIndent(logs, "", "  ")
	w.Write(jsonResult)
}

// LogsHandler xu ly POST de luu log va GET de tra log da giai ma.
func LogsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		renderLogsByMode(w, r, viewModePlain)
		return
	}

	if r.Method == http.MethodPost {
		var incomingLog models.SystemLog
		err := json.NewDecoder(r.Body).Decode(&incomingLog)
		if err != nil {
			http.Error(w, `{"error": "Dữ liệu JSON không hợp lệ"}`, http.StatusBadRequest)
			return
		}
		err = database.SaveLog(incomingLog)
		if err != nil {
			http.Error(w, `{"error": "Lỗi khi lưu vào Database"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"message": "Log đã được mã hóa AES và lưu trữ an toàn!"}`))
		return
	}
	http.Error(w, `{"error": "Method không được hỗ trợ"}`, http.StatusMethodNotAllowed)
}

// RawMaskHandler tra ve log da mask tinh tren du lieu AES tho.
func RawMaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	renderLogsByMode(w, r, viewModeStatic)
}

// DecryptMaskHandler tra ve log da giai ma va mask tinh.
func DecryptMaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	renderLogsByMode(w, r, viewModeStatic)
}

// RandomMaskHandler tra ve log da giai ma va mask ngau nhien.
func RandomMaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	renderLogsByMode(w, r, viewModeRandom)
}

// InsertMaskHandler tra ve log da giai ma va mask chen nhan.
func InsertMaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	renderLogsByMode(w, r, viewModeInsert)
}

// ShuffleMaskHandler tra ve log da giai ma va xao tron du lieu.
func ShuffleMaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	renderLogsByMode(w, r, viewModeShuffle)
}

// StartServer dang ky routes va chay HTTP server.
func StartServer() {
	http.HandleFunc("/api/auth/login", AuthLoginHandler)
	http.HandleFunc("/api/auth/logout", withAuth(AuthLogoutHandler))
	http.HandleFunc("/api/auth/me", withAuth(AuthMeHandler))
	http.HandleFunc("/api/admin/dev-view-mode", withAdmin(AdminDevViewModeHandler))

	http.HandleFunc("/api/logs", withAuth(LogsHandler))
	http.HandleFunc("/api/logs/raw-mask", withAuth(RawMaskHandler))
	http.HandleFunc("/api/logs/decrypted-mask", withAuth(DecryptMaskHandler))
	http.HandleFunc("/api/logs/random-mask", withAuth(RandomMaskHandler))
	http.HandleFunc("/api/logs/insert-mask", withAuth(InsertMaskHandler))
	http.HandleFunc("/api/logs/shuffle-mask", withAuth(ShuffleMaskHandler))

	fmt.Println("🌐 Centralized Log Server đang chạy tại: http://localhost:8080")
	fmt.Println("---------------------------------------------------------")
	fmt.Println("👉 1. Xem chữ thật              : http://localhost:8080/api/logs")
	fmt.Println("👉 2. Mask dấu sao (***)        : http://localhost:8080/api/logs/decrypted-mask")
	fmt.Println("👉 3. Mask Ngẫu Nhiên (Random)  : http://localhost:8080/api/logs/random-mask")
	fmt.Println("👉 4. Mask Chèn nhãn [REDACTED] : http://localhost:8080/api/logs/insert-mask")
	fmt.Println("👉 5. Mask Xáo Trộn (Shuffle)   : http://localhost:8080/api/logs/shuffle-mask")
	fmt.Println("---------------------------------------------------------")

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Printf("❌ Lỗi khởi động Server: %v\n", err)
	}
}
