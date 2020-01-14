package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/atchett/go-rest-api-jwt/models"
	"github.com/dgrijalva/jwt-go"
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

// TokenVerifyMiddleware - validates the token - gives access to protected
func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
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
				RespondWithError(w, http.StatusUnauthorized, errObj)
				return
			}

			if token.Valid {
				// invoke function getting called on
				// in this case the protected endpoint function handler
				next.ServeHTTP(w, r)
			} else {
				errObj.Message = err.Error()
				RespondWithError(w, http.StatusUnauthorized, errObj)
				return
			}
		} else {
			errObj.Message = "Invalid Token"
			RespondWithError(w, http.StatusUnauthorized, errObj)
			return
		}
	})
}
