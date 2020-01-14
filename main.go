package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/subosito/gotenv"
	"go-jwt/driver"
	"go-jwt/models"
	"golang.org/x/crypto/bcrypt"
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
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleware(protectedEndpoint)).Methods("GET")
	router.HandleFunc("/app", TokenVerifyMiddleware(app)).Methods("GET")
	router.HandleFunc("/some", TokenVerifyMiddleware(some)).Methods("GET")
	router.HandleFunc("/cantsee", TokenVerifyMiddleware(cantsee)).Methods("GET")

	log.Println("Listen on port 8000....")
	log.Fatal(http.ListenAndServe(":8000", router))
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user models.User
	var error models.Error

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email is missing"
		utils.respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "Password is missing"
		utils.respondWithError(w, http.StatusBadRequest, error)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		log.Fatal(err)
	}

	// change hash to string
	user.Password = string(hash)

	stmt := "insert into users (email, password) values($1, $2) RETURNING id;"
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)
	if err != nil {
		fmt.Println(err)
		error.Message = "Server Error"
		utils.respondWithError(w, http.StatusInternalServerError, error)
		return
	}

	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	utils.responseJSON(w, user)

	// spew gives really detailed output
	//spew.Dump(user)

}

func generateToken(user models.User) (string, error) {
	secret := os.Getenv("APP_SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "jwtCourse",
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Fatal(err)
	}
	return tokenString, nil

}

func login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	var error models.Error
	var jwt models.JWT
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email is missing"
		utils.respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "Password is missing"
		utils.respondWithError(w, http.StatusBadRequest, error)
		return
	}

	pwd := user.Password
	row := db.QueryRow("select * from users where email = $1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "The user does not exist"
			utils.respondWithError(w, http.StatusBadRequest, error)
			return
		}
		log.Fatal(err)
	}

	hashPwd := user.Password

	err = bcrypt.CompareHashAndPassword([]byte(hashPwd), []byte(pwd))
	if err != nil {
		error.Message = "Invalid password"
		utils.respondWithError(w, http.StatusBadRequest, error)
		return
	}
	token, err := generateToken(user)
	if err != nil {
		log.Fatal(err)
	}
	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	utils.responseJSON(w, jwt)
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
				utils.respondWithError(w, http.StatusUnauthorized, errObj)
				return
			}

			if token.Valid {
				// invoke function getting called on
				// in this case the protected endpoint function handler
				next.ServeHTTP(w, r)
			} else {
				errObj.Message = err.Error()
				utils.respondWithError(w, http.StatusUnauthorized, errObj)
				return
			}
		} else {
			errObj.Message = "Invalid Token"
			utils.respondWithError(w, http.StatusUnauthorized, errObj)
			return
		}
	})
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndpoint")
}

func app(w http.ResponseWriter, r *http.Request) {
	fmt.Println("app")
}

func some(w http.ResponseWriter, r *http.Request) {
	fmt.Println("some")
}

func cantsee(w http.ResponseWriter, r *http.Request) {
	fmt.Println("cantsee")
}
