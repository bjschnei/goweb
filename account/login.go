package account

import (
	"github.com/gorilla/schema"
	"github.com/gorilla/sessions"

	"database/sql"
	"net/http"
)

type loginForm struct {
	Email    string
	Password string
	Token    string `schema:"csrf_token"`
}

type loginContext struct {
	Form  *loginForm
	Error string
}

func newLoginContext() *loginContext {
	return &loginContext{Form: &loginForm{}}
}

func (c *loginContext) setToken(t string) {
	c.Form.Token = t
}

type loginHandler struct {
	db *sql.DB
	s  sessions.Store
}

func newLoginHandler(db *sql.DB, s sessions.Store) http.Handler {
	return &loginHandler{db, s}
}

func (l loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	if u, err := loadUserByEmail(l.db, c.Form.Email); err != nil {
		c.Error = "Invalid username/password"
		executeContextTemplate(w, "login.html", c)
	} else if !u.isCorrectPassword(c.Form.Password) {
		c.Error = "Invalid username/password"
		executeContextTemplate(w, "login.html", c)
	} else if err := u.saveToSession(l.s, w, r); err != nil {
		c.Error = err.Error()
		executeContextTemplate(w, "login.html", c)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		// User logged in, redirect
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func executeContextTemplate(w http.ResponseWriter, n string, c interface{}) {
	err := templates.ExecuteTemplate(w, n, c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
