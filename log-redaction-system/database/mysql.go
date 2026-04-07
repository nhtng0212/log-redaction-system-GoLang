package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
)

var DB *sql.DB

func ConnectDB() {
	// Nạp biến môi trường từ file .env
	err := godotenv.Load()
	if err != nil {
		log.Println("⚠️ Cảnh báo: Không tìm thấy file .env. Hệ thống sẽ thử dùng biến môi trường của OS.")
	}

	// Lấy cấu hình từ môi trường, nếu không có thì gán mặc định (Fallback an toàn)
	dbUser := os.Getenv("DB_USER")
	if dbUser == "" {
		dbUser = "root"
	}

	dbPass := os.Getenv("DB_PASS")
	if dbPass == "" {
		dbPass = "123456"
	}

	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "127.0.0.1"
	}

	dbName := os.Getenv("DB_NAME")
	if dbName == "" {
		dbName = "log_redaction_db"
	}

	// Tạo chuỗi DSN kết nối MySQL
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?parseTime=true", dbUser, dbPass, dbHost, dbName)

	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("[-] Lỗi khởi tạo trình điều khiển MySQL: %v", err)
	}

	err = DB.Ping()
	if err != nil {
		log.Fatalf("[-] Lỗi kết nối tới MySQL Database: %v\n💡 Hãy chắc chắn bạn đã bật MySQL trên XAMPP/WAMP.", err)
	}

	fmt.Println("✅ Đã kết nối MySQL Local thành công!")
}
