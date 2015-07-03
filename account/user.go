package account

import (
	"database/sql"
	"encoding/gob"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

const (
	Session = "ACCOUNT"
	UserKey = "USER"
)

// TODO: make hash and algo private
// Add field to keep track if user was loaded from db.
// loading user from session sets field to false and fields lazy loaded
// from db when requested.
type User struct {
	ID           int64
	Email        string
	PasswordHash []byte
	PasswordAlgo string
}

func newUser(email string) *User {
	return &User{Email: email}
}

func loadUserByEmail(db *sql.DB, email string) (*User, error) {
	u := newUser(email)
	err := db.QueryRow(
		"select id, password_hash, password_algo from users where email = ?",
		email).
		Scan(&u.ID, &u.PasswordHash, &u.PasswordAlgo)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func UserFromRequest(store sessions.Store, r *http.Request) (*User, error) {
	s, err := store.Get(r, Session)
	if err != nil {
		return nil, err
	}
	ui, ok := s.Values[UserKey]
	if !ok {
		return nil, nil
	}

	u, ok := ui.(*User)
	if !ok {
		return nil, fmt.Errorf("user object not stored in user key.  got %v", ui)
	}
	return u, nil
}

func (u User) saveToSession(store sessions.Store, w http.ResponseWriter, r *http.Request) error {
	session, err := store.Get(r, Session)
	if err != nil {
		return err
	}
	session.Values[UserKey] = u
	return session.Save(r, w)
}

func (u *User) insert(db *sql.DB) error {
	r, err := db.Exec(
		"INSERT INTO users (email, password_hash, password_algo) VALUES ($1, $2, $3)",
		u.Email,
		u.PasswordHash,
		u.PasswordAlgo)

	if err != nil {
		return err
	}
	u.ID, err = r.LastInsertId()
	if err != nil {
		return err
	}
	return nil
}

func (u *User) setPassword(password string) error {
	ph, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = ph
	u.PasswordAlgo = "BCRYPT"
	return nil
}

func (u *User) changePassword(db *sql.DB, p string) error {
	if err := u.setPassword(p); err != nil {
		return err
	}

	_, err := db.Exec(
		"UPDATE users SET password_hash=$1, password_algo=$2 WHERE id=$3",
		u.PasswordHash, u.PasswordAlgo, u.ID)

	return err
}

func (u User) isCorrectPassword(p string) bool {
	return bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(p)) == nil
}

func init() {
	gob.Register(&User{})
}
