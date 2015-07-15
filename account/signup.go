package account

import (
	"database/sql"
	"net/http"
	"net/mail"

	"github.com/gorilla/schema"
	"github.com/gorilla/sessions"
	sqlite "github.com/mattn/go-sqlite3"
)

const MIN_PASS_LEN = 4

type signupPostHandler struct {
	db *sql.DB
	s  sessions.Store
}

type signupForm struct {
	Email     string
	Password  string
	Password2 string
	Errors    map[string]string
	Token     string `schema:"csrf_token"`
}

type signupContext struct {
	PassLen int
	Form    *signupForm
}

func newSignupPostHandler(db *sql.DB, s sessions.Store) *signupPostHandler {
	return &signupPostHandler{db, s}
}

func newSignupForm() *signupForm {
	return &signupForm{Errors: make(map[string]string)}
}

func newSignupContext() *signupContext {
	return &signupContext{
		Form:    newSignupForm(),
		PassLen: MIN_PASS_LEN}
}

func (c *signupContext) setToken(t string) {
	c.Form.Token = t
}

func (su signupPostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	decoder := schema.NewDecoder()
	c := newSignupContext()
	err = decoder.Decode(c.Form, r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !c.Form.validate() {
		err = templates.ExecuteTemplate(w, "signup.html", c)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	u, err := c.Form.createUser(su.db)
	if err != nil {
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

	if err = u.saveToSession(su.s, w, r); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	http.Redirect(w, r, "/", http.StatusFound)
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
	u := newUser(f.Email)

	if err := u.setPassword(f.Password); err != nil {
		return nil, err
	}
	if err := u.insert(db); err != nil {
		return nil, err
	}
	return u, nil
}
