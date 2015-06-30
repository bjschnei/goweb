package account

import (
	"crypto/rand"
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
	config oauth2.Config
	store  sessions.Store
}

func newOAuthFacebook(config oauth2.Config, store sessions.Store) *oAuthFacebook {
	return &oAuthFacebook{config, store}
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
