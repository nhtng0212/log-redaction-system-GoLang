// Package database cung cap ket noi MySQL cho he thong log redaction.
package database

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

// ConnectDB mo ket noi MySQL va kiem tra bang ping.
func ConnectDB() {
	dsn := "root:12345678@tcp(127.0.0.1:3306)/log_redaction_db"
	var err error
	DB, err = sql.Open("mysql", dsn)

	if err != nil {
			log.Fatalf("[-] Lỗi mở kết nối: %v", err)
	}

	err = DB.Ping()
	if err != nil {
			log.Fatalf("[-] Lỗi Ping DB: %v", err)
	}

	fmt.Println("Đã kết nối MySQL thành công!")
}