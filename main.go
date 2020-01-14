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
	"github.com/lib/pq"
	"github.com/subosito/gotenv"
	"golang.org/x/crypto/bcrypt"
)

// User - Models the user
type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// JWT - Models the token
type JWT struct {
	Token string `json:"token"`
}

// Error - models the error
type Error struct {
	Message string `json:"message"`
}

var (
	_  = gotenv.Load()
	db *sql.DB
)

func main() {

	pgURL, err := pq.ParseURL(os.Getenv("LOCAL_SQL_URL"))
	if err != nil {
		log.Fatal(err)
	}

	db, err = sql.Open("postgres", pgURL)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

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

func respondWithError(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email is missing"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "Password is missing"
		respondWithError(w, http.StatusBadRequest, error)
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
		respondWithError(w, http.StatusInternalServerError, error)
		return
	}

	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	responseJSON(w, user)

	// spew gives really detailed output
	//spew.Dump(user)

}

func generateToken(user User) (string, error) {
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
	var user User
	var error Error
	var jwt JWT
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email is missing"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "Password is missing"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	pwd := user.Password
	row := db.QueryRow("select * from users where email = $1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "The user does not exist"
			respondWithError(w, http.StatusBadRequest, error)
			return
		}
		log.Fatal(err)
	}

	hashPwd := user.Password

	err = bcrypt.CompareHashAndPassword([]byte(hashPwd), []byte(pwd))
	if err != nil {
		error.Message = "Invalid password"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}
	token, err := generateToken(user)
	if err != nil {
		log.Fatal(err)
	}
	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	responseJSON(w, jwt)
}

// TokenVerifyMiddleware - validates the token - gives access to protected
func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errObj Error
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
				respondWithError(w, http.StatusUnauthorized, errObj)
				return
			}

			if token.Valid {
				// invoke function getting called on
				// in this case the protected endpoint function handler
				next.ServeHTTP(w, r)
			} else {
				errObj.Message = err.Error()
				respondWithError(w, http.StatusUnauthorized, errObj)
				return
			}
		} else {
			errObj.Message = "Invalid Token"
			respondWithError(w, http.StatusUnauthorized, errObj)
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
