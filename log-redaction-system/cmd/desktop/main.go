package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

const API_URL = "http://localhost:8080/api/logs"

// Khai báo cấu trúc dữ liệu để hứng JSON
type SystemLog struct {
	ID          int    `json:"id"`
	Timestamp   string `json:"timestamp"`
	ServiceName string `json:"service_name"`
	IPAddress   string `json:"ip_address"`
	APIToken    string `json:"api_token"`
	Message     string `json:"message"`
}

func main() {
	// 1. Khởi tạo App và Cửa sổ
	myApp := app.New()
	window := myApp.NewWindow("🛡️ Hệ Thống Quản Lý Log Bảo Mật AES-128")
	window.Resize(fyne.NewSize(900, 600))

	// Biến toàn cục lưu dữ liệu hiển thị trên bảng
	var tableData [][]string
	header := []string{"ID", "Service", "IP Address", "API Token", "Message"}
	tableData = append(tableData, header)

	lblTime := widget.NewLabel("⏱️ Thời gian thực thi: 0 ms")

	// ==========================================
	// PHẦN 1: BẢNG HIỂN THỊ DỮ LIỆU
	// ==========================================
	table := widget.NewTable(
		func() (int, int) { return len(tableData), 5 },
		func() fyne.CanvasObject {
			return widget.NewLabel("Template text for sizing")
		},
		func(i widget.TableCellID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(tableData[i.Row][i.Col])
			if i.Row == 0 {
				o.(*widget.Label).TextStyle = fyne.TextStyle{Bold: true}
			}
		},
	)
	table.SetColumnWidth(0, 50)
	table.SetColumnWidth(1, 120)
	table.SetColumnWidth(2, 150)
	table.SetColumnWidth(3, 200)
	table.SetColumnWidth(4, 300)

	// Hàm hỗ trợ gọi API GET
	fetchData := func(endpoint string) {
		start := time.Now()
		resp, err := http.Get(endpoint)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Không thể kết nối Server! Chắc chắn Server đang chạy.\n%v", err), window)
			return
		}
		defer resp.Body.Close()

		var logs []SystemLog
		json.NewDecoder(resp.Body).Decode(&logs)

		// Xóa dữ liệu cũ, giữ lại Header
		tableData = [][]string{header}
		for _, log := range logs {
			row := []string{
				fmt.Sprintf("%d", log.ID),
				log.ServiceName,
				log.IPAddress,
				log.APIToken,
				log.Message,
			}
			tableData = append(tableData, row)
		}

		elapsed := time.Since(start).Milliseconds()
		lblTime.SetText(fmt.Sprintf("⏱️ Thời gian gọi API & Load bảng: %d ms", elapsed))
		table.Refresh() // Bắt buộc gọi để vẽ lại bảng
	}

	// ==========================================
	// PHẦN 2: CÁC NÚT ĐIỀU KHIỂN (GET)
	// ==========================================
	btnRaw := widget.NewButton("1. Xem Chữ Thật", func() { fetchData(API_URL) })
	btnStatic := widget.NewButton("2. Mask Dấu Sao (***)", func() { fetchData(API_URL + "/decrypted-mask") })
	btnRandom := widget.NewButton("3. Mask Ngẫu Nhiên", func() { fetchData(API_URL + "/random-mask") })
	btnInsert := widget.NewButton("4. Mask Chèn [REDACTED]", func() { fetchData(API_URL + "/insert-mask") })

	actionBox := container.NewHBox(btnRaw, btnStatic, btnRandom, btnInsert)

	// ==========================================
	// PHẦN 3: FORM NHẬP DỮ LIỆU (POST)
	// ==========================================
	inputService := widget.NewEntry()
	inputService.SetPlaceHolder("VD: PaymentAPI")

	inputIP := widget.NewEntry()
	inputIP.SetPlaceHolder("VD: 192.168.1.100")

	inputToken := widget.NewEntry()
	inputToken.SetPlaceHolder("VD: sk_live_secret_9999")

	inputMsg := widget.NewEntry()
	inputMsg.SetPlaceHolder("VD: Giao dịch thành công")

	form := widget.NewForm(
		widget.NewFormItem("Tên Service:", inputService),
		widget.NewFormItem("Địa chỉ IP:", inputIP),
		widget.NewFormItem("API Token:", inputToken),
		widget.NewFormItem("Nội dung:", inputMsg),
	)

	btnPost := widget.NewButton("🚀 Bắn Data (Mã hóa AES vào DB)", func() {
		if inputService.Text == "" || inputIP.Text == "" || inputToken.Text == "" {
			dialog.ShowInformation("Thiếu thông tin", "Vui lòng điền đủ các trường!", window)
			return
		}

		payload := map[string]string{
			"service_name": inputService.Text,
			"ip_address":   inputIP.Text,
			"api_token":    inputToken.Text,
			"message":      inputMsg.Text,
		}
		jsonData, _ := json.Marshal(payload)

		start := time.Now()
		resp, err := http.Post(API_URL, "application/json", bytes.NewBuffer(jsonData))

		if err != nil || resp.StatusCode != http.StatusCreated {
			dialog.ShowError(fmt.Errorf("Lỗi gửi dữ liệu!"), window)
			return
		}

		elapsed := time.Since(start).Milliseconds()
		dialog.ShowInformation("Thành công", fmt.Sprintf("Đã lưu và mã hóa an toàn!\nThời gian: %d ms", elapsed), window)

		// Xóa trắng form và load lại bảng
		inputService.SetText("")
		inputIP.SetText("")
		inputToken.SetText("")
		inputMsg.SetText("")
		fetchData(API_URL)
	})

	formBox := container.NewVBox(
		widget.NewLabelWithStyle("📥 Thêm Log Mới", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		form,
		btnPost,
	)

	mainLayout := container.NewBorder(
		container.NewVBox(formBox, widget.NewSeparator(), widget.NewLabelWithStyle("👁️ Xem Dữ Liệu", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), actionBox, lblTime), // Nằm trên cùng
		nil,   
		nil,   
		nil,   
		table, 
	)

	window.SetContent(mainLayout)

	go fetchData(API_URL)

	window.ShowAndRun()
}
