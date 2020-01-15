package utils

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/atchett/go-rest-api-jwt/models"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// RespondWithError - sends the error back to the client
func RespondWithError(w http.ResponseWriter, status int, error models.Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

// ResponseJSON - the response
func ResponseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

// LogFatal - log fatal errors
func LogFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// LogToTerm - log fatal errors
func LogToTerm(msg string) {
	log.Println(msg)
}

// GenerateToken - generates an auth token
func GenerateToken(user models.User) (string, error) {
	secret := os.Getenv("APP_SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "jwtCourse",
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		LogFatal(err)
	}
	return tokenString, nil

}

// ComparePasswords - wrapper function to compare hashed pwds
func ComparePasswords(hashedPassword []byte, password []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashedPassword, password)
	if err != nil {
		LogToTerm("Invalid password")
		return false
	}
	return true

}
