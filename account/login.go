package account

import (
	"github.com/gorilla/schema"
	"golang.org/x/crypto/bcrypt"

	"database/sql"
	"net/http"
)

type loginForm struct {
	Email    string
	Password string
}

type loginContext struct {
	Form  *loginForm
	Error string
}

func newLoginContext() *loginContext {
	return &loginContext{Form: &loginForm{}}
}

func loginHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	decoder := schema.NewDecoder()
	c := newLoginContext()
	err = decoder.Decode(c.Form, r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if u, err := loadUserByEmail(db, c.Form.Email); err != nil {
		c.Error = "Invalid username/password"
		executeLoginTemplate(w, c)
	} else if err = bcrypt.CompareHashAndPassword(
		u.password_hash, []byte(c.Form.Password)); err != nil {
		c.Error = "Invalid username/password"
		executeLoginTemplate(w, c)
	} else if err := u.saveToSession(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// User logged in, redirect
	http.Redirect(w, r, "/", http.StatusFound)
}

func executeLoginTemplate(w http.ResponseWriter, c *loginContext) {
	err := templates.ExecuteTemplate(w, "login.html", c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
