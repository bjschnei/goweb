package account

import (
	"database/sql"
	"net/http"

	"github.com/gorilla/schema"
	"github.com/gorilla/sessions"
)

type loginForm struct {
	Email    string
	Password string
	Token    string `schema:"csrf_token"`
}

type loginContext struct {
	Form  *loginForm
	Error string
	FBURL string
}

func newLoginContext(fbURL string) *loginContext {
	return &loginContext{Form: &loginForm{}, FBURL: fbURL}
}

func (c *loginContext) setToken(t string) {
	c.Form.Token = t
}

type loginPostHandler struct {
	db *sql.DB
	s  sessions.Store
	fb *oAuthFacebook
}

type loginGetHandler struct {
	db *sql.DB
	s  sessions.Store
	fb *oAuthFacebook
}

func newLoginPostHandler(db *sql.DB, s sessions.Store, fb *oAuthFacebook) http.Handler {
	return &loginPostHandler{db, s, fb}
}

func newLoginGetHandler(db *sql.DB, s sessions.Store, fb *oAuthFacebook) http.Handler {
	return &loginGetHandler{db, s, fb}
}

func (l loginPostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	decoder := schema.NewDecoder()
	url, err := l.fb.GetLoginURL(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c := newLoginContext(url)
	err = decoder.Decode(c.Form, r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if u, err := loadUserByEmail(l.db, c.Form.Email); err != nil {
		c.Error = "Invalid username/password"
		executeContextTemplate(w, "login.html", c)
	} else if !u.isCorrectPassword(c.Form.Password) {
		c.Error = "Invalid username/password"
		executeContextTemplate(w, "login.html", c)
	} else if err := u.saveToSession(l.s, w, r); err != nil {
		c.Error = err.Error()
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		redirectAfterLogin(l.s, w, r)
	}
}

func (l loginGetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if url, err := l.fb.GetLoginURL(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		templateHandler("login.html", newLoginContext(url), w, r)
	}
}

func executeContextTemplate(w http.ResponseWriter, n string, c interface{}) {
	err := templates.ExecuteTemplate(w, n, c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
