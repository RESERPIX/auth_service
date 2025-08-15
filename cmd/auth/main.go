package main

import (
	"github.com/RESERPIX/auth-service/internal/db"
)

func main() {
	pg := db.ConnectPostgres("localhost", "5432", "user", "password", "authdb")
	_ = pg

	db.Migrate(pg)
}