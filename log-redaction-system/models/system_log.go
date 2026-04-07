package models

// SystemLog đại diện cho một dòng log trong hệ thống
type SystemLog struct {
	ID          int    `json:"id"`
	Timestamp   string `json:"timestamp"`
	ServiceName string `json:"service_name"`
	IPAddress   string `json:"ip_address"`
	APIToken    string `json:"api_token"`
	Salt        string `json:"-"`
	Message     string `json:"message"`
}

// User đại diện cho tài khoản quản trị/dev
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// LoginRequest dùng để hứng dữ liệu người dùng gửi lên khi đăng nhập
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
