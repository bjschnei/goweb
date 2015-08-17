package account

import (
	"database/sql"
	"net/http"

	"github.com/gorilla/schema"
	"github.com/gorilla/sessions"
)

type changePasswordPostHandler struct {
	db *sql.DB
	s  sessions.Store
}

type changePasswordGetHandler struct {
	s sessions.Store
}

type ChangePasswordForm struct {
	OldPassword        string
	NewPassword        string
	ConfirmNewPassword string
	Token              string `schema:"csrf_token"`
}

type changePasswordContext struct {
	Form    *ChangePasswordForm
	HasOldPassword bool
	Error   string
	Message string
}

func newChangePasswordPostHandler(db *sql.DB, s sessions.Store) *changePasswordPostHandler {
	return &changePasswordPostHandler{db, s}
}

func newChangePasswordGetHandler(s sessions.Store) *changePasswordGetHandler {
	return &changePasswordGetHandler{s}
}

func newChangePasswordContext(u *User) *changePasswordContext {
	return &changePasswordContext{Form: &ChangePasswordForm{},
																HasOldPassword: len(u.PasswordHash) != 0}
}

func (c *changePasswordContext) setToken(t string) {
	c.Form.Token = t
}

func (h changePasswordGetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, err := UserFromRequest(h.s, r)
	if err != nil || u == nil {
		http.Error(w, "user not logged in", http.StatusUnauthorized)
		return
	}
	templateHandler("change_password.html", newChangePasswordContext(u), w, r)
}

func (h changePasswordPostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	u, err := UserFromRequest(h.s, r)
	if err != nil || u == nil {
		http.Error(w, "user not logged in", http.StatusUnauthorized)
		return
	}

	c := newChangePasswordContext(u)
	err = schema.NewDecoder().Decode(c.Form, r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if c.HasOldPassword && !u.isCorrectPassword(c.Form.OldPassword) {
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

  nc := newChangePasswordContext(u)
  nc.Error = c.Error
  nc.Message = c.Message
	templateHandler("change_password.html", nc, w, r)
}

func (h changePasswordPostHandler) updatePassword(
	c changePasswordContext, u *User, w http.ResponseWriter, r *http.Request) (passwordError string, internalError error) {
  if c.HasOldPassword && !u.isCorrectPassword(c.Form.OldPassword) {
		passwordError = "Incorrect old password"
	} else if len(c.Form.NewPassword) < MIN_PASS_LEN {
		passwordError = "Passwords is too short"
	} else if c.Form.ConfirmNewPassword != c.Form.NewPassword {
		passwordError = "New password doesn't match confirmation"
	} else if err := u.changePassword(h.db, c.Form.NewPassword); err != nil {
		return passwordError, err
	} else if err := u.saveToSession(h.s, w, r); err != nil {
		return passwordError, err
	}
	return passwordError, nil
}
