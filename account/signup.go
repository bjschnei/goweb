package account

import (
	"github.com/gorilla/schema"
	sqlite "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"

	"database/sql"
	"net/http"
	"net/mail"
)

const MIN_PASS_LEN = 4

type signupForm struct {
	Email     string
	Password  string
	Password2 string
	Errors    map[string]string
}

type signupContext struct {
	PassLen int
	Form    *signupForm
}

func newSignupForm() *signupForm {
	return &signupForm{Errors: make(map[string]string)}
}

func newSignupContext() *signupContext {
	return &signupContext{
		Form:    newSignupForm(),
		PassLen: MIN_PASS_LEN}
}

func signupHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	decoder := schema.NewDecoder()
	c := newSignupContext()
	err = decoder.Decode(c.Form, r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if !c.Form.validate() {
		err = templates.ExecuteTemplate(w, "signup.html", c)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if _, err := c.Form.createUser(db); err != nil {
		if isExistingUserError(err) {
			c.Form.Errors["Email"] = "User already exists"
			if err := templates.ExecuteTemplate(w, "signup.html", c); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Mazl Tov!"))
}

func isExistingUserError(err error) bool {
	if sqliteErr, ok := err.(sqlite.Error); ok {
		if sqliteErr.Code == sqlite.ErrConstraint {
			return true
		}
	}
	return false
}

func (f *signupForm) validate() bool {
	_, err := mail.ParseAddress(f.Email)
	if err != nil {
		f.Errors["Email"] = "Invalid email address"
		return false
	}

	if len(f.Password) < MIN_PASS_LEN {
		f.Errors["Password"] = "Passwords is too short"
		return false
	}

	if f.Password != f.Password2 {
		f.Errors["Password"] = "Passwords don't match"
		return false
	}
	return true
}

func (f *signupForm) createUser(db *sql.DB) (*User, error) {
	ph, err := bcrypt.GenerateFromPassword([]byte(f.Password), 12)
	if err != nil {
		return nil, err
	}
	u := newUser(f.Email, ph, "BCRYPT")
	if err := u.insert(db); err != nil {
		return nil, err
	}
	return u, nil
}
