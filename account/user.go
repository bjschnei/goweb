package account

import (
	"github.com/gorilla/sessions"

	"database/sql"
	"encoding/gob"
	"fmt"
	"net/http"
)

const (
	Session = "ACCOUNT"
	UserKey = "USER"
)

var store = sessions.NewCookieStore([]byte("todo_loaded_secret"))

type User struct {
	ID            int
	Email         string
	password_hash []byte
	password_algo string
}

func newUser(email string, password_hash []byte, password_algo string) *User {
	return &User{
		Email:         email,
		password_hash: password_hash,
		password_algo: password_algo}
}

func loadUserByEmail(db *sql.DB, email string) (*User, error) {
	var id int
	var password_hash []byte
	var password_algo string

	err := db.QueryRow(
		"select id, password_hash, password_algo from users where email = ?",
		email).
		Scan(&id, &password_hash, &password_algo)
	if err != nil {
		return nil, err
	}
	u := newUser(email, password_hash, password_algo)
	u.ID = id
	return u, nil
}

func UserFromRequest(r *http.Request) (*User, error) {
	session, err := store.Get(r, Session)
	if err != nil {
		return nil, err
	}
	ui, ok := session.Values[UserKey]
	if !ok {
		return nil, nil
	}

	u, ok := ui.(*User)
	if !ok {
		return nil, fmt.Errorf("user object not stored in user key.  got %v", ui)
	}
	return u, nil
}

func (u User) saveToSession(w http.ResponseWriter, r *http.Request) error {
	session, err := store.Get(r, Session)
	if err != nil {
		return err
	}
	session.Values[UserKey] = u
	return session.Save(r, w)
}

func (u User) removeFromSession(w http.ResponseWriter, r *http.Request) error {
	session, err := store.Get(r, Session)
	if err != nil {
		return err
	}
	delete(session.Values, UserKey)
	return session.Save(r, w)
}

func (u User) insert(db *sql.DB) error {
	_, err := db.Exec(
		"INSERT INTO users (email, password_hash, password_algo) VALUES ($1, $2, $3)",
		u.Email,
		u.password_hash,
		u.password_algo)
	return err
}

func init() {
	gob.Register(&User{})
}
