package main

import (
	"database/sql"
	"net/http"

	"github.com/atchett/go-rest-api-jwt/controllers"
	"github.com/atchett/go-rest-api-jwt/driver"
	"github.com/atchett/go-rest-api-jwt/utils"
	"github.com/gorilla/mux"
	"github.com/subosito/gotenv"
)

var (
	_  = gotenv.Load()
	db *sql.DB
)

func main() {

	db = driver.ConnectDB()
	router := mux.NewRouter()

	controller := controllers.Controller{}

	router.HandleFunc("/signup", controller.Signup(db)).Methods("POST")
	router.HandleFunc("/login", controller.Login(db)).Methods("POST")
	router.HandleFunc("/protected", controller.TokenVerifyMiddleware(controller.Protected())).Methods("GET")

	utils.LogToTerm("Listen on port 8000....")
	utils.LogFatal(http.ListenAndServe(":8000", router))
}
