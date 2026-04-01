package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"log-redaction-system/database"
	"log-redaction-system/models"
)

type contextKey string

const userContextKey = contextKey("authUser")

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type modeRequest struct {
	Mode string `json:"mode"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func AuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method không được hỗ trợ"})
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Dữ liệu JSON không hợp lệ"})
		return
	}

	user, err := database.ValidateCredentials(req.Username, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Sai tài khoản hoặc mật khẩu"})
		return
	}

	token, err := database.CreateSession(*user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Không thể tạo phiên đăng nhập"})
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{Token: token, Username: user.Username, Role: user.Role})
}

func AuthLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method không được hỗ trợ"})
		return
	}
	user := getAuthUser(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Chưa đăng nhập"})
		return
	}

	if err := database.DeleteSession(user.Token); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Không thể đăng xuất"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Đăng xuất thành công"})
}

func AuthMeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method không được hỗ trợ"})
		return
	}
	user := getAuthUser(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Chưa đăng nhập"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"username": user.Username,
		"role":     user.Role,
	})
}

func AdminDevViewModeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		mode, err := database.GetDevViewMode()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Không thể đọc cấu hình"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"mode": mode})
		return
	}

	if r.Method == http.MethodPut {
		var req modeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Dữ liệu JSON không hợp lệ"})
			return
		}
		if err := database.SetDevViewMode(req.Mode); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Mode không hợp lệ"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "Cập nhật cấu hình thành công", "mode": req.Mode})
		return
	}

	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method không được hỗ trợ"})
}

func withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Thiếu token đăng nhập"})
			return
		}
		token := strings.TrimPrefix(authorization, "Bearer ")
		token = strings.TrimSpace(token)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Token không hợp lệ"})
			return
		}

		session, err := database.GetSessionByToken(token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Phiên đăng nhập hết hạn hoặc không hợp lệ"})
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, session)
		next(w, r.WithContext(ctx))
	}
}

func withAdmin(next http.HandlerFunc) http.HandlerFunc {
	return withAuth(func(w http.ResponseWriter, r *http.Request) {
		user := getAuthUser(r)
		if user == nil || user.Role != "admin" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "Bạn không có quyền admin"})
			return
		}
		next(w, r)
	})
}

func getAuthUser(r *http.Request) *models.SessionInfo {
	v := r.Context().Value(userContextKey)
	if v == nil {
		return nil
	}
	user, ok := v.(*models.SessionInfo)
	if !ok {
		return nil
	}
	return user
}
