package account

import (
	"database/sql"
	"io/ioutil"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestSchema(t *testing.T) {
	db, err := setupDB()
	if err != nil {
		t.Fatal("Failed to setup db schema %v", err)
	}
	defer db.Close()
}

func TestUserPassword(t *testing.T) {
	u := newUser("some.email.com")
	if u.isCorrectPassword("") {
		t.Error("Expected no password to be incorrect")
	}
	u.setPassword("foobar")
	if u.isCorrectPassword("bar") {
		t.Error("Expected incorrect password to fail")
	}

	if !u.isCorrectPassword("foobar") {
		t.Error("Expected correct password to pass")
	}
}

func TestSaveAndLoadUser(t *testing.T) {
	db, err := setupDB()
	if err != nil {
		t.Fatal("Failed to setup db schema %v", err)
	}

	u := newUser("some@email.com")
	err = u.insert(db)
	if err != nil {
		t.Fatal("Failed to insert user")
	}
	if u.ID != 1 {
		t.Errorf("Failed to set user id, expected 1 got %v", u.ID)
	}

	u2, err := loadUserByEmail(db, "wrong@email.com")
	if err == nil {
		t.Errorf("Expected to get an error but got user %v", u2)
	}

	u2, err = loadUserByEmail(db, u.Email)
	if err != nil {
		t.Fatalf("Expected to get a user, got %v", err)
	}

	if u.Email != u2.Email || u.ID != u2.ID {
		t.Fatalf("Got wrong user, expected %v got %v", u, u2)
	}
}

func setupDB() (*sql.DB, error) {
	schema, err := ioutil.ReadFile("../db.schema")
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", ":memory:")
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
