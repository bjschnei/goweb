package account

import (
	"database/sql"
	"encoding/gob"
	"fmt"
	"log"
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
	ID               int64
	Email            string
	passwordHash     []byte
	passwordAlgo     string
	isPasswordLoaded bool
}

type authUser struct {
	id              int64
	authID          int64
	user            *User
	authType        string
	token           string
	tokenExpiration time.Time
}

func newUser(email string) *User {
	return &User{Email: email}
}

func newAuthUser(user *User, authID int64, authType, token string, tokenExpiration time.Time) *authUser {
	return &authUser{
		user:            user,
		authID:          authID,
		authType:        authType,
		token:           token,
		tokenExpiration: tokenExpiration}
}

func loadUserByEmail(db *sql.DB, email string) (*User, error) {
	u := newUser(email)
	err := db.QueryRow(
		"SELECT id, password_hash, password_algo FROM Users WHERE email = ?",
		email).
		Scan(&u.ID, &u.passwordHash, &u.passwordAlgo)
	if err != nil {
		return nil, err
	}
	u.isPasswordLoaded = true
	return u, nil
}

func loadUserByID(db *sql.DB, id int64) (*User, error) {
	u := &User{}
	u.ID = id
	err := db.QueryRow(
		"SELECT email, password_hash, password_algo FROM Users WHERE id = ?",
		id).
		Scan(&u.Email, &u.passwordHash, &u.passwordAlgo)
	if err != nil {
		return nil, err
	}
	u.isPasswordLoaded = true
	return u, nil
}

func loadUserByAuth(db *sql.DB, authID int64, authType string) (*authUser, error) {
	var id int64
	var userID int64
	var token string
	var expiration int64
	err := db.QueryRow(
		"SELECT id, user_id, token, expiration FROM Auth WHERE auth_id = ? AND type = ?",
		authID, authType).Scan(&id, &userID, &token, &expiration)

	if err != nil {
		return nil, err
	}
	u, err := loadUserByID(db, userID)
	if err != nil {
		return nil, err
	}
	au := newAuthUser(u, authID, authType, token, time.Unix(expiration, 0))
	au.id = id
	return au, nil
}

func createUserByAuth(db *sql.DB, authID int64, authType, token, email string,
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
			tx.Rollback()
			return nil, err
		}
	}

	au := newAuthUser(u, authID, authType, token, tokenExpiration)
	err = au.insert(db)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, err
	}
	return au, nil
}

func getOrInsertAuthUser(db *sql.DB, authID int64, authType, token, email string,
	tokenExpiration time.Time) (*authUser, error) {
	if u, err := loadUserByAuth(db, authID, authType); err == nil {
		return u, nil
	}
	return createUserByAuth(db, authID, authType, token, email, tokenExpiration)
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
	u.isPasswordLoaded = false
	return u, nil
}

func (au *authUser) insert(db *sql.DB) error {
	r, err := db.Exec(
		"INSERT INTO Auth (user_id, auth_id, type, token, expiration) VALUES ($1, $2, $3, $4, $5)",
		au.user.ID,
		au.authID,
		au.authType,
		au.token,
		au.tokenExpiration.Unix())
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
		u.passwordHash,
		u.passwordAlgo)

	if err != nil {
		return err
	}
	u.ID, err = r.LastInsertId()
	return err
}

func (u *User) setPassword(password string) error {
	ph, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.passwordHash = ph
	u.passwordAlgo = "BCRYPT"
	u.isPasswordLoaded = true
	return nil
}

func (u *User) changePassword(db *sql.DB, p string) error {
	if err := u.setPassword(p); err != nil {
		return err
	}

	_, err := db.Exec(
		"UPDATE Users SET password_hash=$1, password_algo=$2 WHERE id=$3",
		u.passwordHash, u.passwordAlgo, u.ID)

	return err
}

func (u *User) isCorrectPassword(db *sql.DB, p string) (bool, error) {
	// For auth users with no set password, do not allow empty string comparison.
	hp, err := u.HasPassword(db)
	log.Printf("Has password %v %v", hp, err)
	if err != nil {
		return false, err
	}
	if !hp {
		return false, nil
	}
	return bcrypt.CompareHashAndPassword(u.passwordHash, []byte(p)) == nil, nil
}

func (u *User) loadPassword(db *sql.DB) error {
	err := db.QueryRow(
		"SELECT password_hash, password_algo FROM Users WHERE id = ?", u.ID).
		Scan(&u.passwordHash, &u.passwordAlgo)
	if err != nil {
		return err
	}
	u.isPasswordLoaded = true
	return nil
}

func (u *User) HasPassword(db *sql.DB) (bool, error) {
	if !u.isPasswordLoaded {
		if err := u.loadPassword(db); err != nil {
			return false, err
		}
	}
	if len(u.passwordHash) == 0 {
		return false, nil
	}
	return true, nil
}

func init() {
	gob.Register(&User{})
}
