package account

import (
	"database/sql"
	"net/http"

	"github.com/gorilla/schema"
	"github.com/gorilla/sessions"
)

type changePasswordHandler struct {
	db *sql.DB
	s  sessions.Store
}

type ChangePasswordForm struct {
	OldPassword        string
	NewPassword        string
	ConfirmNewPassword string
	Token              string `schema:"csrf_token"`
}

type changePasswordContext struct {
	Form    *ChangePasswordForm
	Error   string
	Message string
}

func newChangePasswordHandler(db *sql.DB, s sessions.Store) *changePasswordHandler {
	return &changePasswordHandler{db, s}
}

func newChangePasswordContext() *changePasswordContext {
	return &changePasswordContext{Form: &ChangePasswordForm{}}
}

func (c *changePasswordContext) setToken(t string) {
	c.Form.Token = t
}

func (h changePasswordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	decoder := schema.NewDecoder()
	c := newChangePasswordContext()
	err = decoder.Decode(c.Form, r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if u, err := UserFromRequest(h.s, r); err != nil || u == nil {
		http.Error(w, "user not logged in", http.StatusUnauthorized)
		return
	} else if !u.isCorrectPassword(c.Form.OldPassword) {
		c.Error = "Incorrect old password"
	} else if len(c.Form.NewPassword) < MIN_PASS_LEN {
		c.Error = "Passwords is too short"
	} else if c.Form.ConfirmNewPassword != c.Form.NewPassword {
		c.Error = "New password doesn't match confirmation"
	} else if err := u.changePassword(h.db, c.Form.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if err := u.saveToSession(h.s, w, r); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		c.Message = "Password changed"
	}

	executeContextTemplate(w, "change_password.html", c)
}
