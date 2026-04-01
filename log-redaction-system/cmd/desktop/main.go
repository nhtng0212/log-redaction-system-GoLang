// Package main khoi dong ung dung desktop de xem va gui log.
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

const API_URL = "http://localhost:8080/api/logs"
const AUTH_URL = "http://localhost:8080/api/auth"
const ADMIN_URL = "http://localhost:8080/api/admin"

// SystemLog dinh nghia ban ghi log nhan tu API.
type SystemLog struct {
	ID          int    `json:"id"`
	Timestamp   string `json:"timestamp"`
	ServiceName string `json:"service_name"`
	IPAddress   string `json:"ip_address"`
	APIToken    string `json:"api_token"`
	Message     string `json:"message"`
}

type LoginResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type AppSession struct {
	Token    string
	Username string
	Role     string
}

const tokenDisplayLimit = 36

func shortenForTable(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "..."
}

func doJSONRequest(method string, url string, token string, payload any, out any) error {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewBuffer(b)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return err
		}
	}
	return nil
}

// main tao giao dien desktop va tuong tac voi API.
func main() {
	myApp := app.New()
	window := myApp.NewWindow("🛡️ Hệ Thống Quản Lý Log Bảo Mật AES-128")
	window.Resize(fyne.NewSize(900, 600))
	session := &AppSession{}

	var showLogin func()
	var showDashboard func()

	showDashboard = func() {
		var tableData [][]string
		var rawLogs []SystemLog
		header := []string{"ID", "Service", "IP Address", "API Token", "Message"}
		tableData = append(tableData, header)

		lblTime := widget.NewLabel("⏱️ Thời gian thực thi: 0 ms")
		lblUser := widget.NewLabel(fmt.Sprintf("👤 %s (%s)", session.Username, session.Role))

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
		table.SetColumnWidth(2, 230)
		table.SetColumnWidth(3, 360)
		table.SetColumnWidth(4, 240)
		table.OnSelected = func(id widget.TableCellID) {
			if id.Row == 0 || id.Col != 3 {
				return
			}
			index := id.Row - 1
			if index < 0 || index >= len(rawLogs) {
				return
			}
			fullToken := rawLogs[index].APIToken
			if shortenForTable(fullToken, tokenDisplayLimit) == fullToken {
				return
			}
			dialog.ShowInformation("API Token đầy đủ", fullToken, window)
		}

		fetchData := func(endpoint string) {
			start := time.Now()
			var logs []SystemLog
			err := doJSONRequest(http.MethodGet, endpoint, session.Token, nil, &logs)
			if err != nil {
				dialog.ShowError(fmt.Errorf("Không thể tải dữ liệu: %v", err), window)
				return
			}
			rawLogs = logs

			tableData = [][]string{header}
			for _, log := range logs {
				row := []string{
					fmt.Sprintf("%d", log.ID),
					log.ServiceName,
					log.IPAddress,
					shortenForTable(log.APIToken, tokenDisplayLimit),
					log.Message,
				}
				tableData = append(tableData, row)
			}

			elapsed := time.Since(start).Milliseconds()
			lblTime.SetText(fmt.Sprintf("⏱️ Thời gian gọi API & Load bảng: %d ms", elapsed))
			table.Refresh()
		}

		btnRaw := widget.NewButton("1. Xem Chữ Thật", func() { fetchData(API_URL) })
		btnStatic := widget.NewButton("2. Mask Dấu Sao (***)", func() { fetchData(API_URL + "/decrypted-mask") })
		btnRandom := widget.NewButton("3. Mask Ngẫu Nhiên", func() { fetchData(API_URL + "/random-mask") })
		btnInsert := widget.NewButton("4. Mask Chèn [REDACTED]", func() { fetchData(API_URL + "/insert-mask") })
		btnShuffle := widget.NewButton("5. Mask Xáo Trộn", func() { fetchData(API_URL + "/shuffle-mask") })

		var actionBox fyne.CanvasObject
		if session.Role == "admin" {
			actionBox = container.NewHBox(btnRaw, btnStatic, btnRandom, btnInsert, btnShuffle)
		} else {
			devHint := widget.NewLabel("Dev chỉ xem dữ liệu theo cấu hình masking của admin")
			actionBox = container.NewVBox(devHint, widget.NewButton("Xem dữ liệu", func() { fetchData(API_URL) }))
		}

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

			start := time.Now()
			err := doJSONRequest(http.MethodPost, API_URL, session.Token, payload, nil)
			if err != nil {
				dialog.ShowError(fmt.Errorf("Lỗi gửi dữ liệu: %v", err), window)
				return
			}

			elapsed := time.Since(start).Milliseconds()
			dialog.ShowInformation("Thành công", fmt.Sprintf("Đã lưu và mã hóa an toàn!\nThời gian: %d ms", elapsed), window)

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

		btnLogout := widget.NewButton("Đăng xuất", func() {
			_ = doJSONRequest(http.MethodPost, AUTH_URL+"/logout", session.Token, nil, nil)
			session.Token = ""
			session.Username = ""
			session.Role = ""
			showLogin()
		})

		topPanel := container.NewVBox(container.NewHBox(lblUser, btnLogout))
		if session.Role == "admin" {
			topPanel.Add(formBox)
			topPanel.Add(widget.NewSeparator())
		}
		topPanel.Add(widget.NewLabelWithStyle("👁️ Xem Dữ Liệu", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
		topPanel.Add(actionBox)
		topPanel.Add(lblTime)

		configBox := container.NewVBox()
		if session.Role == "admin" {
			modeSelect := widget.NewSelect([]string{"plain", "static", "random", "insert", "shuffle"}, nil)
			modeSelect.SetSelected("static")

			btnLoadMode := widget.NewButton("Tải mode hiện tại", func() {
				var result map[string]string
				err := doJSONRequest(http.MethodGet, ADMIN_URL+"/dev-view-mode", session.Token, nil, &result)
				if err != nil {
					dialog.ShowError(fmt.Errorf("Không tải được mode: %v", err), window)
					return
				}
				modeSelect.SetSelected(result["mode"])
			})

			btnSaveMode := widget.NewButton("Lưu mode cho Dev", func() {
				payload := map[string]string{"mode": modeSelect.Selected}
				err := doJSONRequest(http.MethodPut, ADMIN_URL+"/dev-view-mode", session.Token, payload, nil)
				if err != nil {
					dialog.ShowError(fmt.Errorf("Không lưu được mode: %v", err), window)
					return
				}
				dialog.ShowInformation("Thành công", "Đã cập nhật chế độ xem cho tài khoản dev", window)
			})

			configBox = container.NewVBox(
				widget.NewSeparator(),
				widget.NewLabelWithStyle("⚙️ Cấu Hình Quyền Xem Của Dev", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
				widget.NewForm(widget.NewFormItem("dev_view_mode", modeSelect)),
				container.NewHBox(btnLoadMode, btnSaveMode),
			)
		}

		mainLayout := container.NewBorder(
			container.NewVBox(topPanel, configBox),
			nil,
			nil,
			nil,
			table,
		)

		window.SetContent(mainLayout)
		go fetchData(API_URL)
	}

	showLogin = func() {
		inputUsername := widget.NewEntry()
		inputUsername.SetPlaceHolder("admin hoặc dev")

		inputPassword := widget.NewPasswordEntry()
		inputPassword.SetPlaceHolder("Nhập mật khẩu")

		form := widget.NewForm(
			widget.NewFormItem("Username:", inputUsername),
			widget.NewFormItem("Password:", inputPassword),
		)

		btnLogin := widget.NewButton("Đăng nhập", func() {
			if inputUsername.Text == "" || inputPassword.Text == "" {
				dialog.ShowInformation("Thiếu thông tin", "Vui lòng nhập username và password", window)
				return
			}

			payload := map[string]string{
				"username": inputUsername.Text,
				"password": inputPassword.Text,
			}

			var resp LoginResponse
			err := doJSONRequest(http.MethodPost, AUTH_URL+"/login", "", payload, &resp)
			if err != nil {
				dialog.ShowError(fmt.Errorf("Đăng nhập thất bại: %v", err), window)
				return
			}

			session.Token = resp.Token
			session.Username = resp.Username
			session.Role = resp.Role
			showDashboard()
		})

		loginLayout := container.NewVBox(
			widget.NewLabelWithStyle("🔐 Đăng Nhập Hệ Thống", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			form,
			btnLogin,
			widget.NewLabel("Tài khoản dev sẽ xem dữ liệu theo cấu hình từ admin."),
		)

		window.SetContent(container.NewCenter(loginLayout))
	}

	showLogin()

	window.ShowAndRun()
}
