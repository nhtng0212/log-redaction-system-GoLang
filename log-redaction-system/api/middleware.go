package api

import (
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware kiểm tra Token và Quyền của người gọi API
func AuthMiddleware(requiredRole string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// 1. Lấy Token từ Header Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error": "Yêu cầu đăng nhập (Thiếu Token)!"}`, http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// 2. Giải mã Token (CHÚ Ý: Lấy cả biến err để bắt lỗi)
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			jwtSecret := os.Getenv("JWT_SECRET")
			if jwtSecret == "" {
				jwtSecret = "ACT_Tung_Nguyen_JWT_Secret_2026" // Fallback
			}
			return []byte(jwtSecret), nil
		})

		// 3. BẪY LỖI NIL POINTER (Tấm khiên chống sập Server)
		if err != nil || token == nil || !token.Valid {
			http.Error(w, `{"error": "Token không hợp lệ hoặc đã hết hạn!"}`, http.StatusUnauthorized)
			return
		}

		// 4. Kiểm tra tính hợp lệ và Quyền (Role)
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			userRole := claims["role"].(string)

			// Admin được phép xem mọi thứ. Nếu API yêu cầu Admin mà User là Dev -> Chặn!
			if requiredRole == "admin" && userRole != "admin" {
				http.Error(w, `{"error": "Bạn không có quyền xem dữ liệu gốc!"}`, http.StatusForbidden)
				return
			}

			// Hợp lệ -> Cho phép đi tiếp vào API
			next.ServeHTTP(w, r)
		} else {
			// Bẫy lỗi phụ nếu cấu trúc Token không thể parse thành MapClaims
			http.Error(w, `{"error": "Không thể đọc dữ liệu từ Token!"}`, http.StatusUnauthorized)
		}
	}
}
