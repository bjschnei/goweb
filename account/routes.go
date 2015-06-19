package account

import (
	"github.com/gorilla/mux"

	"database/sql"
	"html/template"
	"net/http"
)

var templates = template.Must(template.ParseGlob("templates/account/*"))

func CreateRoutes(sr *mux.Router, db *sql.DB) error {
	sr.Methods("GET").
		Path("/signup").
		Handler(requireNoUser(func(w http.ResponseWriter, r *http.Request) {
		templateHandler("signup.html", w, r)
	}))

	sr.Methods("POST").
		Path("/signup").
		HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signupHandler(db, w, r)
	})

	sr.Methods("GET").
		Path("/login").
		Handler(requireNoUser(func(w http.ResponseWriter, r *http.Request) {
		templateHandler("login.html", w, r)
	}))

	sr.Methods("POST").
		Path("/login").
		HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginHandler(db, w, r)
	})

	sr.Methods("GET").
		Path("/logout").
		HandlerFunc(logoutHandler)

	return nil
}

func templateHandler(tmpl string, w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, tmpl, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func requireNoUser(h func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := UserFromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		if u != nil {
			http.Redirect(w, r, "/", http.StatusFound)
		} else {
			h(w, r)
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
