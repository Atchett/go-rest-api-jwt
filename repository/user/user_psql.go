package userrepository

import (
	"database/sql"

	"github.com/atchett/go-rest-api-jwt/models"
	"github.com/atchett/go-rest-api-jwt/utils"
)

// UserRepository - empty struct for methods
type UserRepository struct{}

// Signup - interacts with the database to signup the user
func (u UserRepository) Signup(db *sql.DB, user models.User) models.User {

	sqlStmt := "insert into users (email, password) values($1, $2) RETURNING id;"
	err := db.QueryRow(sqlStmt, user.Email, user.Password).Scan(&user.ID)
	utils.LogFatal(err)

	user.Password = ""

	return user
}

// Login - interacts with the database to allow the user to login
func (u UserRepository) Login(db *sql.DB, user models.User) (models.User, error) {
	row := db.QueryRow("select * from users where email = $1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		return user, err
	}
	return user, nil
}
