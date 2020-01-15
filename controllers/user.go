package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/atchett/go-rest-api-jwt/models"
	userRepository "github.com/atchett/go-rest-api-jwt/repository/user"
	"github.com/atchett/go-rest-api-jwt/utils"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

var users []models.User

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
		if err != nil {
			if err == sql.ErrNoRows {
				error.Message = "The user does not exist"
				utils.RespondWithError(w, http.StatusBadRequest, error)
				return
			}
			utils.LogFatal(err)
		}

		hashPwd := user.Password
		token, err := utils.GenerateToken(user)
		if err != nil {
			utils.LogFatal(err)
		}

		isValidPassword := utils.ComparePasswords([]byte(hashPwd), []byte(pwd))
		if isValidPassword {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Authorization", token)
			jwt.Token = token
			utils.ResponseJSON(w, jwt)
		}

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

// TokenVerifyMiddleware - validates the token - gives access to protected endpoints
func (c Controller) TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errObj models.Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]
			token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte(os.Getenv("APP_SECRET")), nil
			})

			if err != nil {
				errObj.Message = err.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, errObj)
				return
			}

			if token.Valid {
				// invoke function getting called on
				// in this case the protected endpoint function handler
				next.ServeHTTP(w, r)
			} else {
				errObj.Message = err.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, errObj)
				return
			}
		} else {
			errObj.Message = "Invalid Token"
			utils.RespondWithError(w, http.StatusUnauthorized, errObj)
			return
		}
	})
}
