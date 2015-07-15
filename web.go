package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"text/template"

	"github.com/bjschnei/goweb/account"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"github.com/namsral/flag"
)

var (
	templates = template.Must(template.ParseFiles(
		"templates/index.html",
	))

	configFile = flag.String("config", "config.json",
		"file containing configuration parameters in json")
	port = flag.Int("port", 80, "Port web server listens on")
)

type config struct {
	OauthFB struct {
		ID     string
		Secret string
	}
	DomainName   string
	CookieSecret []byte
}

type homeContext struct {
	U *account.User
}

func homepageHandler(w http.ResponseWriter, r *http.Request, store sessions.Store) {
	u, err := account.UserFromRequest(store, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = templates.ExecuteTemplate(w, "index.html", &homeContext{U: u})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func readConfig(filename string) (*config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	c := &config{}
	err = dec.Decode(c)
	return c, err
}

func main() {
	flag.Parse()
	log.SetOutput(os.Stderr)
	log.Printf("Using port %v and config file %v", *port, *configFile)
	db, err := sql.Open("sqlite3", "web.db")
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := readConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	wd = wd + string(os.PathSeparator)

	if err = account.InitializeTemplates(wd); err != nil {
		log.Fatal(err)
	}

	addr := "http://" + cfg.DomainName
	if *port != 80 {
		addr += ":" + strconv.Itoa(*port)
	}

	store := sessions.NewCookieStore(cfg.CookieSecret)

	am := account.NewAccountManager(store, db, addr,
		account.NewFacebookClient(cfg.OauthFB.ID, cfg.OauthFB.Secret))
	mx := mux.NewRouter()
	mx.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		homepageHandler(w, r, store)
	})

	asr := mx.PathPrefix("/account").Subrouter()
	if err := am.CreateRoutes(asr); err != nil {
		log.Fatal("unable to create account routes", err)
	}
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(*port), handlers.CompressHandler(mx)))
}
