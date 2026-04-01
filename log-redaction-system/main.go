// Package main khoi dong API server cho he thong log redaction.
package main

import (
	"log-redaction-system/api"
	"log-redaction-system/database"
)

// main ket noi DB va chay HTTP server.
func main() {
	database.ConnectDB()
	api.StartServer()
}
