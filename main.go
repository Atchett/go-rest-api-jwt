package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/subosito/gotenv"
	"go-rest-api-jwt/controllers"
	"go-rest-api-jwt/driver"
	"go-rest-api-jwt/utils"
)

var (
	db *sql.DB
	// removes the need for init
	// https://medium.com/random-go-tips/init-without-init-ebf2f62e7c4a
	_ = gotenv.Load()
)

func main() {

	db = driver.ConnectDB()
	router := mux.NewRouter()
	controller := controllers.Controller{}

	router.HandleFunc("/signup", controller.Signup(db)).Methods("POST")
	router.HandleFunc("/login", controller.Login(db)).Methods("POST")
	router.HandleFunc("/protected", utils.TokenVerifyMiddleware(controller.Protected(db))).Methods("GET")

	log.Println("Listen on port 8000....")
	log.Fatal(http.ListenAndServe(":8000", router))
}
