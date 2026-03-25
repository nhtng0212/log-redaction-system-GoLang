package main

import (
	"log-redaction-system/api"
	"log-redaction-system/database"
)

func main() {
	database.ConnectDB()

	// maskedLogs := database.GetAndMaskLogs()

	// fmt.Println("\n KẾT QUẢ DỮ LIỆU SAU KHI CHE GIẤU ")

	// for _, log := range maskedLogs {
	// 	fmt.Printf("[ID: %d | Service: %s]\n", log.ID, log.ServiceName)
	// 	fmt.Printf("   |─ IP: %s\n", log.IPAddress)
	// 	fmt.Printf("   ├─ Token: %s\n", log.APIToken)
	// 	fmt.Printf("   └─ Message: %s\n\n", log.Message)
	// }

	api.StartServer()

	// http://localhost:8080/api/logs
}
