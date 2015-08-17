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
	Form           *ChangePasswordForm
	HasOldPassword bool
	Error          string
	Message        string
}

func newChangePasswordPostHandler(db *sql.DB, s sessions.Store) *changePasswordPostHandler {
	return &changePasswordPostHandler{db, s}
}

func newChangePasswordGetHandler(db *sql.DB, s sessions.Store) *changePasswordGetHandler {
	return &changePasswordGetHandler{db, s}
}

func newChangePasswordContext(db *sql.DB, u *User) (*changePasswordContext, error) {
	hp, err := u.HasPassword(db)
	if err != nil {
		return nil, err
	}
	return &changePasswordContext{Form: &ChangePasswordForm{},
		HasOldPassword: hp}, nil
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
	c, err := newChangePasswordContext(h.db, u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	templateHandler("change_password.html", c, w, r)
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

	c, err := newChangePasswordContext(h.db, u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	err = schema.NewDecoder().Decode(c.Form, r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	perr, ierr := h.updatePassword(c, u, w, r)
	if ierr != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(perr) != 0 {
		c.Message = perr
	} else {
		c.Message = "Password changed"
	}

	nc, err := newChangePasswordContext(h.db, u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	nc.Error = c.Error
	nc.Message = c.Message
	templateHandler("change_password.html", nc, w, r)
}

func (h changePasswordPostHandler) updatePassword(
	c *changePasswordContext, u *User, w http.ResponseWriter, r *http.Request) (passwordError string, err error) {
	hp, err := u.HasPassword(h.db)
	if err != nil {
		return
	}

	if hp {
		cp, err := u.isCorrectPassword(h.db, c.Form.OldPassword)
		if err != nil {
			return "", err
		}
		if !cp {
			return "Incorrect old password", nil
		}
	}

	if len(c.Form.NewPassword) < MIN_PASS_LEN {
		passwordError = "Passwords is too short"
	} else if c.Form.ConfirmNewPassword != c.Form.NewPassword {
		passwordError = "New password doesn't match confirmation"
	}
	err = u.changePassword(h.db, c.Form.NewPassword)
	return
}
