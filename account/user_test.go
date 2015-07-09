package account

import (
	"database/sql"
	"io/ioutil"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestSchema(t *testing.T) {
	_, err := setupDB()
	if err != nil {
		t.Fatal("Failed to setup db schema %v", err)
	}
}

func setupDB() (*sql.DB, error) {
	schema, err := ioutil.ReadFile("../db.schema")
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", ":memory")
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(string(schema))
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
