package account

import (
	"database/sql"
	"log"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/justinas/alice"
	"github.com/justinas/nosurf"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

var (
	templates *template.Template
)

type csrfForm interface {
	setToken(string)
}

type AccountManager struct {
	db         *sql.DB
	store      sessions.Store
	serverAddr string
	baseURL    *url.URL
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
	return &AccountManager{
		db:         db,
		store:      s,
		serverAddr: dn,
		baseURL:    nil,
		fb:         newOAuthFacebook(db, s, fb.Config)}
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

func (am AccountManager) RequireUserMiddleware() func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, err := UserFromRequest(am.store, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if u == nil {
				if err := am.storeNext(w, r); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				http.Redirect(w, r, am.baseURL.String()+"/login", http.StatusFound)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
}

func (am AccountManager) storeNext(w http.ResponseWriter, r *http.Request) error {
	s, err := am.store.Get(r, Session)
	if err != nil {
		return err
	}
	s.Values["postLoginPath"] = r.URL.Path
	return s.Save(r, w)
}

func redirectAfterLogin(store sessions.Store, w http.ResponseWriter, r *http.Request) {
	s, err := store.Get(r, Session)
	if err != nil {
		log.Print("unable to get request session, redirecting to homepage")
		http.Redirect(w, r, "/", http.StatusFound)
	}
	p, ok := s.Values["postLoginPath"]
	if ok {
		ps, ok := p.(string)
		if !ok {
			log.Print("postLoginPath is not a string, redirecting to homepage")
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		http.Redirect(w, r, ps, http.StatusFound)
		delete(s.Values, "postLoginPath")
		if err := s.Save(r, w); err != nil {
			log.Print("Unable to remove postLoginPath from session")
		}
	} else {
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (am *AccountManager) CreateRoutes(sr *mux.Router) error {

	l := sr.Methods("GET").
		Path("/login").
		Handler(alice.New(nosurf.NewPure, am.RequireNoUserMiddleware()).Then(
		newLoginGetHandler(am.db, am.store, am.fb)))

	b, err := l.URL()
	if err != nil {
		return err
	}
	am.baseURL, err = url.Parse(strings.TrimSuffix(b.Path, "/login"))
	if err != nil {
		return err
	}

	am.fb.config.RedirectURL = am.serverAddr + am.baseURL.Path + "/loginfb"
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
		Handler(nosurf.New(newSignupPostHandler(am.db, am.store)))

	sr.Methods("GET").
		Path("/change_password").
		Handler(alice.New(nosurf.NewPure, am.RequireUserMiddleware()).Then(
		newChangePasswordGetHandler(am.db, am.store)))

	sr.Methods("POST").
		Path("/change_password").
		Handler(nosurf.New(newChangePasswordPostHandler(am.db, am.store)))

	return nil
}

func templateHandler(tmpl string, f csrfForm, w http.ResponseWriter, r *http.Request) {
	f.setToken(nosurf.Token(r))
	err := templates.ExecuteTemplate(w, tmpl, f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func InitializeTemplates(root string) error {
	var err error
	templates, err = template.ParseGlob(root + "templates/account/*")
	return err
}
