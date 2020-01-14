package controllers

import (
	"database/sql"
	"fmt"
	"net/http"
)

// Protected - the protected end point
func (c Controller) Protected(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("success.")
	}
}
