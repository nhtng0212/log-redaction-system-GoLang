package database

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"log-redaction-system/models"
)

const DefaultDevViewMode = "static"

var validDevModes = map[string]bool{
	"plain":   true,
	"static":  true,
	"random":  true,
	"insert":  true,
	"shuffle": true,
}

// HashPasswordSHA256 tao hash SHA-256 cho mat khau.
func HashPasswordSHA256(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ValidateCredentials kiem tra username/password va tra ve user.
func ValidateCredentials(username string, rawPassword string) (*models.AppUser, error) {
	query := "SELECT id, username, password_hash, role FROM app_users WHERE username = ? LIMIT 1"
	var user models.AppUser
	err := DB.QueryRow(query, username).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("invalid username or password")
		}
		return nil, err
	}

	if user.PasswordHash != HashPasswordSHA256(rawPassword) {
		return nil, errors.New("invalid username or password")
	}
	return &user, nil
}

// CreateSession tao token session moi cho user.
func CreateSession(user models.AppUser) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)

	query := "INSERT INTO user_sessions (token, user_id, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 24 HOUR))"
	if _, err := DB.Exec(query, token, user.ID); err != nil {
		return "", err
	}
	return token, nil
}

// GetSessionByToken lay thong tin session hop le theo token.
func GetSessionByToken(token string) (*models.SessionInfo, error) {
	query := `
SELECT u.id, u.username, u.role, s.token
FROM user_sessions s
JOIN app_users u ON u.id = s.user_id
WHERE s.token = ? AND s.expires_at > NOW()
LIMIT 1`
	var info models.SessionInfo
	err := DB.QueryRow(query, token).Scan(&info.UserID, &info.Username, &info.Role, &info.Token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("invalid or expired session")
		}
		return nil, err
	}
	return &info, nil
}

// DeleteSession xoa token session (logout).
func DeleteSession(token string) error {
	_, err := DB.Exec("DELETE FROM user_sessions WHERE token = ?", token)
	return err
}

// GetDevViewMode lay mode hien thi du lieu cho vai tro dev.
func GetDevViewMode() (string, error) {
	var mode string
	err := DB.QueryRow("SELECT config_value FROM app_config WHERE config_key = 'dev_view_mode' LIMIT 1").Scan(&mode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DefaultDevViewMode, nil
		}
		return "", err
	}
	if !validDevModes[mode] {
		return DefaultDevViewMode, nil
	}
	return mode, nil
}

// SetDevViewMode cap nhat mode hien thi du lieu cho dev.
func SetDevViewMode(mode string) error {
	if !validDevModes[mode] {
		return fmt.Errorf("unsupported mode: %s", mode)
	}
	query := `
INSERT INTO app_config (config_key, config_value)
VALUES ('dev_view_mode', ?)
ON DUPLICATE KEY UPDATE config_value = VALUES(config_value), updated_at = CURRENT_TIMESTAMP`
	_, err := DB.Exec(query, mode)
	return err
}
