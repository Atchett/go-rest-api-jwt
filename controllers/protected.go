package controllers

import (
	"fmt"
	"net/http"
)

// Protected - the protected page of the app
func (c Controller) Protected() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("success")
	}
}
