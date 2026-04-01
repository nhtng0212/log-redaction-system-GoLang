package models

// AppUser la tai khoan dang nhap vao he thong.
type AppUser struct {
	ID           int
	Username     string
	PasswordHash string
	Role         string
}

// SessionInfo la thong tin phien dang nhap duoc gan theo token.
type SessionInfo struct {
	UserID   int
	Username string
	Role     string
	Token    string
}
