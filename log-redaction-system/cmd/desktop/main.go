package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

const BASE_URL = "http://localhost:8080/api"

// Biến toàn cục lưu thông tin phiên làm việc
var authToken string
var currentUserRole string

// Cấu trúc hứng dữ liệu
type SystemLog struct {
	ID          int    `json:"id"`
	Timestamp   string `json:"timestamp"`
	ServiceName string `json:"service_name"`
	IPAddress   string `json:"ip_address"`
	APIToken    string `json:"api_token"`
	Message     string `json:"message"`
}

func main() {
	myApp := app.New()
	window := myApp.NewWindow("🛡️ Hệ Thống Quản Lý Log Bảo Mật Kép (AES-KDF & JWT)")
	window.Resize(fyne.NewSize(950, 650))

	// Khởi động vào màn hình Đăng Nhập
	showLoginScreen(window)

	window.ShowAndRun()
}

// ==========================================
// MÀN HÌNH ĐĂNG NHẬP
// ==========================================
func showLoginScreen(window fyne.Window) {
	inputUser := widget.NewEntry()
	inputUser.SetPlaceHolder("Tài khoản (admin hoặc dev)")

	inputPass := widget.NewPasswordEntry()
	inputPass.SetPlaceHolder("Mật khẩu (123456)")

	lblStatus := widget.NewLabel("")

	btnLogin := widget.NewButton("🔐 Đăng Nhập", func() {
		payload := map[string]string{
			"username": inputUser.Text,
			"password": inputPass.Text,
		}
		jsonData, _ := json.Marshal(payload)

		resp, err := http.Post(BASE_URL+"/login", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			lblStatus.SetText("❌ Không thể kết nối tới Server!")
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var result map[string]string
			json.NewDecoder(resp.Body).Decode(&result)

			// Lưu Token và Role
			authToken = result["token"]
			currentUserRole = result["role"]

			dialog.ShowInformation("Thành công", "Xin chào: "+currentUserRole, window)

			// Đổi giao diện sang Bảng điều khiển chính
			showDashboardScreen(window)
		} else {
			lblStatus.SetText("❌ Sai tài khoản hoặc mật khẩu!")
		}
	})

	form := container.NewVBox(
		widget.NewLabelWithStyle("ĐĂNG NHẬP HỆ THỐNG TRUNG TÂM", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewFormItem("Tài khoản:", inputUser).Widget,
		widget.NewFormItem("Mật khẩu:", inputPass).Widget,
		btnLogin,
		lblStatus,
	)

	window.SetContent(container.NewCenter(form))
}

// ==========================================
// MÀN HÌNH BẢNG ĐIỀU KHIỂN CHÍNH
// ==========================================
func showDashboardScreen(window fyne.Window) {
	var tableData [][]string
	header := []string{"ID", "Service", "IP Address", "API Token", "Message"}
	tableData = append(tableData, header)

	lblTime := widget.NewLabel("⏱️ Thời gian API: 0 ms")
	lblUser := widget.NewLabelWithStyle(fmt.Sprintf("👤 Đang đăng nhập: %s", currentUserRole), fyne.TextAlignTrailing, fyne.TextStyle{Italic: true})

	table := widget.NewTable(
		func() (int, int) { return len(tableData), 5 },
		func() fyne.CanvasObject { return widget.NewLabel("Template text for sizing") },
		func(i widget.TableCellID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(tableData[i.Row][i.Col])
			if i.Row == 0 {
				o.(*widget.Label).TextStyle = fyne.TextStyle{Bold: true}
			}
		},
	)
	table.SetColumnWidth(0, 50)
	table.SetColumnWidth(1, 120)
	table.SetColumnWidth(2, 160)
	table.SetColumnWidth(3, 220)
	table.SetColumnWidth(4, 300)

	// HÀM GỌI API (KÈM JWT TOKEN)
	fetchData := func(endpoint string) {
		start := time.Now()

		req, _ := http.NewRequest("GET", BASE_URL+endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+authToken) // ⚠️ Gắn Token vào thẻ đi lại

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Lỗi kết nối Server!"), window)
			return
		}
		defer resp.Body.Close()

		// Kiểm tra quyền
		if resp.StatusCode == http.StatusForbidden {
			dialog.ShowError(fmt.Errorf("⛔ BẠN KHÔNG CÓ QUYỀN TRUY CẬP TÍNH NĂNG NÀY (Chỉ Admin)"), window)
			return
		}

		var logs []SystemLog
		json.NewDecoder(resp.Body).Decode(&logs)

		tableData = [][]string{header}
		for _, log := range logs {
			row := []string{fmt.Sprintf("%d", log.ID), log.ServiceName, log.IPAddress, log.APIToken, log.Message}
			tableData = append(tableData, row)
		}

		elapsed := time.Since(start).Milliseconds()
		lblTime.SetText(fmt.Sprintf("⏱️ Thời gian API & Load: %d ms", elapsed))
		table.Refresh()
	}

	// 4 Nút chức năng gọi 4 API
	btnRaw := widget.NewButton("1. Xem Chữ Thật (Admin)", func() { fetchData("/logs/decrypted") })
	btnStatic := widget.NewButton("2. Mask Dấu Sao (***)", func() { fetchData("/logs/static-mask") })
	btnRandom := widget.NewButton("3. Mask Ngẫu Nhiên", func() { fetchData("/logs/random-mask") })
	btnInsert := widget.NewButton("4. Mask Chèn [REDACTED]", func() { fetchData("/logs/insert-mask") })

	actionBox := container.NewHBox(btnRaw, btnStatic, btnRandom, btnInsert)

	// Form thêm log
	inputService := widget.NewEntry()
	inputIP := widget.NewEntry()
	inputToken := widget.NewEntry()
	inputMsg := widget.NewEntry()

	formBox := container.NewVBox(
		widget.NewLabelWithStyle("📥 Bắn dữ liệu lên Server", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewForm(
			widget.NewFormItem("Tên Service:", inputService),
			widget.NewFormItem("Địa chỉ IP:", inputIP),
			widget.NewFormItem("API Token:", inputToken),
			widget.NewFormItem("Nội dung:", inputMsg),
		),
		widget.NewButton("🚀 Mã hóa AES-KDF và Lưu DB", func() {
			payload := map[string]string{
				"service_name": inputService.Text, "ip_address": inputIP.Text,
				"api_token": inputToken.Text, "message": inputMsg.Text,
			}
			jsonData, _ := json.Marshal(payload)

			req, _ := http.NewRequest("POST", BASE_URL+"/logs", bytes.NewBuffer(jsonData))
			req.Header.Set("Authorization", "Bearer "+authToken) // ⚠️ Gắn Token

			start := time.Now()
			resp, err := http.DefaultClient.Do(req)

			if err != nil || resp.StatusCode != http.StatusCreated {
				bodyBytes, _ := io.ReadAll(resp.Body)
				dialog.ShowError(fmt.Errorf("Lỗi gửi dữ liệu: %s", string(bodyBytes)), window)
				return
			}

			elapsed := time.Since(start).Milliseconds()
			dialog.ShowInformation("Thành công", fmt.Sprintf("Đã mã hóa phái sinh và lưu DB!\nThời gian: %d ms", elapsed), window)

			inputService.SetText("")
			inputIP.SetText("")
			inputToken.SetText("")
			inputMsg.SetText("")

			// Load lại bảng
			if currentUserRole == "admin" {
				fetchData("/logs/decrypted")
			} else {
				fetchData("/logs/static-mask")
			}
		}),
	)

	// Sắp xếp bố cục giao diện
	topSection := container.NewVBox(
		lblUser,
		formBox,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("👁️ Xem Dữ Liệu", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		actionBox,
		lblTime,
	)

	mainLayout := container.NewBorder(topSection, nil, nil, nil, table)
	window.SetContent(mainLayout)

	// Lần đầu mở app, load bảng tùy theo quyền
	if currentUserRole == "admin" {
		go fetchData("/logs/decrypted")
	} else {
		go fetchData("/logs/static-mask")
	}
}
