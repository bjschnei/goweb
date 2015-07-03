package account

import (
	"database/sql"
	"net/http"
	"text/template"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/justinas/alice"
	"github.com/justinas/nosurf"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

var templates = template.Must(template.ParseGlob("templates/account/*"))

type csrfForm interface {
	setToken(string)
}

type AccountManager struct {
	db         *sql.DB
	store      sessions.Store
	serverAddr string
	fb         *oAuthFacebook
}

type OAuthClientConfig struct {
	oauth2.Config
}

func NewFacebookClient(id string, secret string) *OAuthClientConfig {
	c := oauth2.Config{
		ClientID:     id,
		ClientSecret: secret,
		Scopes:       fbScopes,
		Endpoint:     facebook.Endpoint,
	}
	return &OAuthClientConfig{c}
}

func NewAccountManager(
	s sessions.Store, db *sql.DB, dn string, fb *OAuthClientConfig) *AccountManager {
	return &AccountManager{db, s, dn, newOAuthFacebook(db, s, fb.Config)}
}

func (u AccountManager) RequireNoUserMiddleware() func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, err := UserFromRequest(u.store, r)
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
}

func (u AccountManager) RequireUserMiddleware() func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, err := UserFromRequest(u.store, r)
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
}

func (am *AccountManager) CreateRoutes(sr *mux.Router) error {

	l := sr.Methods("GET").
		Path("/login").
		Handler(alice.New(nosurf.NewPure, am.RequireNoUserMiddleware()).Then(
		newLoginGetHandler(am.db, am.store, am.fb)))

	base, err := l.URL()
	if err != nil {
		return err
	}
	am.fb.config.RedirectURL = am.serverAddr + base.String() + "fb"
	sr.Methods("GET").
		Path("/loginfb").
		Handler(alice.New(am.RequireNoUserMiddleware()).
		Then(am.fb))

	sr.Methods("POST").
		Path("/login").
		Handler(nosurf.New(newLoginPostHandler(am.db, am.store, am.fb)))

	sr.Methods("GET").
		Path("/logout").
		HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wipe out the cookie
		http.SetCookie(w, &http.Cookie{Name: Session, MaxAge: -1, Path: "/"})
		http.Redirect(w, r, "/", http.StatusFound)
	})

	sr.Methods("GET").
		Path("/signup").
		Handler(alice.New(nosurf.NewPure, am.RequireNoUserMiddleware()).ThenFunc(
		func(w http.ResponseWriter, r *http.Request) {
			templateHandler("signup.html", newSignupContext(), w, r)
		}))

	sr.Methods("POST").
		Path("/signup").
		Handler(nosurf.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signupHandler(am.db, w, r)
	})))

	sr.Methods("GET").
		Path("/change_password").
		Handler(alice.New(nosurf.NewPure, am.RequireUserMiddleware()).ThenFunc(
		func(w http.ResponseWriter, r *http.Request) {
			templateHandler("change_password.html", newChangePasswordContext(), w, r)
		}))

	sr.Methods("POST").
		Path("/change_password").
		Handler(nosurf.New(newChangePasswordHandler(am.db, am.store)))

	return nil
}

func templateHandler(tmpl string, f csrfForm, w http.ResponseWriter, r *http.Request) {
	f.setToken(nosurf.Token(r))
	err := templates.ExecuteTemplate(w, tmpl, f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
