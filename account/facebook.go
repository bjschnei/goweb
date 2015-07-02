package account

import (
	"crypto/rand"
	"database/sql"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

const (
	sessionState string = "fbAuthState"
)

var fbScopes []string = []string{
	"email",
}

type oAuthFacebook struct {
	db     *sql.DB
	store  sessions.Store
	config oauth2.Config
}

func newOAuthFacebook(db *sql.DB, store sessions.Store, config oauth2.Config) *oAuthFacebook {
	return &oAuthFacebook{db, store, config}
}

func (fb oAuthFacebook) GetLoginURL(w http.ResponseWriter, r *http.Request) (string, error) {
	c := 10
	s := make([]byte, c)
	_, err := rand.Read(s)
	if err != nil {
		return "", err
	}
	state := string(s)

	session, err := fb.store.Get(r, Session)
	if err != nil {
		return "", err
	}
	session.Values[sessionState] = state
	session.Save(r, w)
	return fb.config.AuthCodeURL(state), nil
}

func (fb oAuthFacebook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello"))
}
