package account

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"

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
	state := base64.URLEncoding.EncodeToString(s)

	session, err := fb.store.Get(r, Session)
	if err != nil {
		return "", err
	}
	session.Values[sessionState] = state
	if err := session.Save(r, w); err != nil {
		return "", err
	}
	return fb.config.AuthCodeURL(state), nil
}

func (fb oAuthFacebook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, err := fb.store.Get(r, Session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	vals := r.URL.Query()
	state := vals.Get("state")

	if session.Values[sessionState] != state {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	delete(session.Values, sessionState)

	code := vals.Get("code")
	if err := session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tok, err := fb.config.Exchange(oauth2.NoContext, code)
	if err != nil {
		http.Error(w, "Unable to exchange for token", http.StatusBadRequest)
		return
	}

	client := fb.config.Client(oauth2.NoContext, tok)
	u, err := fb.getFacebookUser(client, tok)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u.user.saveToSession(fb.store, w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (fb oAuthFacebook) getFacebookUser(client *http.Client, tok *oauth2.Token) (*authUser, error) {
	r, err := client.Get("https://graph.facebook.com/me")
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	m := make(map[string]interface{})
	err = json.Unmarshal(body, &m)
	if err != nil {
		return nil, err
	}

	id, err := strconv.ParseInt(m["id"].(string), 10, 64)
	return getOrInsertAuthUser(fb.db, id, "facebook", tok.AccessToken, m["email"].(string), tok.Expiry)
}
