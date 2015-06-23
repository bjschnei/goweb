package main

import (
	"github.com/bjschnei/goweb/account"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"

	"database/sql"
	"html/template"
	"log"
	"net/http"
	"os"
)

var templates = template.Must(template.ParseFiles(
	"templates/index.html",
))

type homeContext struct {
	U *account.User
}

func homepageHandler(w http.ResponseWriter, r *http.Request) {
	u, err := account.UserFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = templates.ExecuteTemplate(w, "index.html", &homeContext{U: u})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {

	log.SetOutput(os.Stderr)
	db, err := sql.Open("sqlite3", "web.db")
	if err != nil {
		log.Fatal(err)
	}
	mx := mux.NewRouter()
	mx.HandleFunc("/", homepageHandler)

	asr := mx.PathPrefix("/account").Subrouter()
	if err := account.CreateRoutes(asr, db); err != nil {
		log.Fatal("unable to create account routes", err)
	}

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = ":8080"
	} else {
		port = ":" + port
	}

	s := &http.Server{
		Addr:    port,
		Handler: mx,
	}
	log.Fatal(s.ListenAndServe())
}
