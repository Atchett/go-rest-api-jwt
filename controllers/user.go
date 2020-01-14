package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/atchett/go-rest-api-jwt/models"
	userRepository "github.com/atchett/go-rest-api-jwt/repository/user"
	"github.com/atchett/go-rest-api-jwt/utils"
	"golang.org/x/crypto/bcrypt"
)

var users []models.User

// Controller - empty struct to contain the methods
type Controller struct{}

// Login - allows the user to login
func (c Controller) Login(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		var error models.Error
		var jwt models.JWT
		json.NewDecoder(r.Body).Decode(&user)

		if user.Email == "" {
			error.Message = "Email is missing"
			utils.RespondWithError(w, http.StatusBadRequest, error)
			return
		}

		if user.Password == "" {
			error.Message = "Password is missing"
			utils.RespondWithError(w, http.StatusBadRequest, error)
			return
		}

		pwd := user.Password

		userRepo := userRepository.UserRepository{}
		user, err := userRepo.Login(db, user)

		log.Println(err)

		if err != nil {
			if err == sql.ErrNoRows {
				error.Message = "The user does not exist"
				utils.RespondWithError(w, http.StatusBadRequest, error)
				return
			}
			utils.LogFatal(err)
		}

		hashPwd := user.Password

		err = bcrypt.CompareHashAndPassword([]byte(hashPwd), []byte(pwd))
		if err != nil {
			error.Message = "Invalid password"
			utils.RespondWithError(w, http.StatusBadRequest, error)
			return
		}
		token, err := utils.GenerateToken(user)
		if err != nil {
			utils.LogFatal(err)
		}
		w.WriteHeader(http.StatusOK)
		jwt.Token = token

		utils.ResponseJSON(w, jwt)
	}
}

// Signup - allows the user to signup
func (c Controller) Signup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		var error models.Error

		json.NewDecoder(r.Body).Decode(&user)

		if user.Email == "" {
			error.Message = "Email is missing"
			utils.RespondWithError(w, http.StatusBadRequest, error)
			return
		}

		if user.Password == "" {
			error.Message = "Password is missing"
			utils.RespondWithError(w, http.StatusBadRequest, error)
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
		if err != nil {
			utils.LogFatal(err)
		}

		// change hash to string
		user.Password = string(hash)

		userRepo := userRepository.UserRepository{}
		user = userRepo.Signup(db, user)

		if err != nil {
			fmt.Println(err)
			error.Message = "Server Error"
			utils.RespondWithError(w, http.StatusInternalServerError, error)
			return
		}

		user.Password = ""
		w.Header().Set("Content-Type", "application/json")
		utils.ResponseJSON(w, user)

	}
}
