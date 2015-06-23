package account

import (
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/justinas/nosurf"

	"database/sql"
	"html/template"
	"net/http"
)

var templates = template.Must(template.ParseGlob("templates/account/*"))

type csrfForm interface {
	setToken(string)
}

func CreateRoutes(sr *mux.Router, db *sql.DB) error {
	sr.Methods("GET").
		Path("/login").
		Handler(alice.New(nosurf.NewPure, requireNoUser).ThenFunc(
		func(w http.ResponseWriter, r *http.Request) {
			templateHandler("login.html", newLoginContext(), w, r)
		}))

	sr.Methods("POST").
		Path("/login").
		Handler(nosurf.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginHandler(db, w, r)
	})))

	sr.Methods("GET").
		Path("/logout").
		HandlerFunc(logoutHandler)

	sr.Methods("GET").
		Path("/signup").
		Handler(alice.New(nosurf.NewPure, requireNoUser).ThenFunc(
		func(w http.ResponseWriter, r *http.Request) {
			templateHandler("signup.html", newSignupContext(), w, r)
		}))

	sr.Methods("POST").
		Path("/signup").
		Handler(nosurf.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signupHandler(db, w, r)
	})))

	sr.Methods("GET").
		Path("/change_password").
		Handler(alice.New(nosurf.NewPure, RequireUser).ThenFunc(
		func(w http.ResponseWriter, r *http.Request) {
			templateHandler("change_password.html", newChangePasswordContext(), w, r)
		}))

	sr.Methods("POST").
		Path("/change_password").
		Handler(nosurf.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		changePasswordHandler(db, w, r)
	})))

	return nil
}

func templateHandler(tmpl string, f csrfForm, w http.ResponseWriter, r *http.Request) {
	f.setToken(nosurf.Token(r))
	err := templates.ExecuteTemplate(w, tmpl, f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func requireNoUser(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := UserFromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		if u != nil {
			http.Redirect(w, r, "/", http.StatusFound)
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

func RequireUser(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := UserFromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		if u == nil {
			http.Redirect(w, r, "/signup", http.StatusFound)
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	u, err := UserFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if u != nil {
		if err := u.removeFromSession(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
