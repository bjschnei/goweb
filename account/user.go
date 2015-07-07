package account

import (
	"database/sql"
	"encoding/gob"
	"fmt"
	"net/http"
	"time"

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

type authUser struct {
	id              int64
	user            *User
	authType        string
	token           string
	tokenExpiration time.Time
}

func newUser(email string) *User {
	return &User{Email: email}
}

func newAuthUser(user *User, authType, token string, tokenExpiration time.Time) *authUser {
	return &authUser{
		user:            user,
		authType:        authType,
		token:           token,
		tokenExpiration: tokenExpiration}
}

func loadUserByEmail(db *sql.DB, email string) (*User, error) {
	u := newUser(email)
	err := db.QueryRow(
		"select id, password_hash, password_algo from Users where email = ?",
		email).
		Scan(&u.ID, &u.PasswordHash, &u.PasswordAlgo)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func loadUserByAuth(db *sql.DB, userID int64, authType string) (*authUser, error) {
	// TODO: implement
	return nil, nil
}

func createUserByAuth(db *sql.DB, userID int64, authType, token, email string,
	tokenExpiration time.Time) (*authUser, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}

	u, err := loadUserByEmail(db, email)
	if err != nil {
		u = newUser(email)
		err = u.insert(db)
		if err != nil {
			return nil, err
		}
	}

	au := newAuthUser(u, authType, token, tokenExpiration)
	err = au.insert(db)
	if err != nil {
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, err
	}
	return au, nil
}

func getOrInsertAuthUser(db *sql.DB, userID int64, authType, token, email string,
	tokenExpiration time.Time) (*authUser, error) {
	if u, _ := loadUserByAuth(db, userID, authType); u != nil {
		return u, nil
	}
	u, err := createUserByAuth(db, userID, authType, token, email, tokenExpiration)
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

func (au *authUser) insert(db *sql.DB) error {
	r, err := db.Exec(
		"INSERT INTO Auth (user_id, type, token, expiration) VALUES ($1, $2, $3, $4)",
		au.user.ID,
		au.authType,
		au.token,
		au.tokenExpiration)
	if err != nil {
		return err
	}
	au.id, err = r.LastInsertId()
	if err != nil {
		return err
	}
	return nil
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
		"INSERT INTO Users (email, password_hash, password_algo) VALUES ($1, $2, $3)",
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
		"UPDATE Users SET password_hash=$1, password_algo=$2 WHERE id=$3",
		u.PasswordHash, u.PasswordAlgo, u.ID)

	return err
}

func (u User) isCorrectPassword(p string) bool {
	return bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(p)) == nil
}

func init() {
	gob.Register(&User{})
}
