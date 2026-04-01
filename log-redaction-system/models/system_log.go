// Package models dinh nghia cac cau truc du lieu cho log.
package models

// SystemLog dai dien mot ban ghi log trao doi qua API va luu trong DB.
type SystemLog struct {
	ID          int    `json:"id"`
	Timestamp   string `json:"timestamp"`
	ServiceName string `json:"service_name"`
	IPAddress   string `json:"ip_address"`
	APIToken    string `json:"api_token"`
	Message     string `json:"message"`
}
