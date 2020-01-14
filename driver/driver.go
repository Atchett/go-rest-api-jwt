package driver

import (
	"database/sql"
	"os"

	"github.com/atchett/go-rest-api-jwt/utils"
	"github.com/lib/pq"
)

var db *sql.DB

// ConnectDB - returns a connection to a DB
func ConnectDB() *sql.DB {

	pgURL, err := pq.ParseURL(os.Getenv("LOCAL_SQL_URL"))
	utils.LogFatal(err)

	db, err = sql.Open("postgres", pgURL)
	utils.LogFatal(err)

	err = db.Ping()
	utils.LogFatal(err)

	return db
}
