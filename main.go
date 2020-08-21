package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/gorilla/sessions"
	"github.com/yuru-dev/SimpleAuthWeb01/oauth2"
	"github.com/yuru-dev/SimpleAuthWeb01/oauth2/user"
)

// https://docs.microsoft.com/ja-jp/azure/active-directory/develop/v2-permissions-and-consent
var exampleScope = []string{"openid", "email", "profile"}

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))
var sessionName = "session"

type PersonCollection struct {
	Persons []Person
}

type Person struct {
	ID      int
	Name    string `json:"name"`
	Email   string `json:"email"`
	Company string `json:"company"`
	City    string `json:"city"`
	Zip     string `json:"zip"`
	Geo     string `json:"geo"`
}

func loadData() (result []Person) {
	raw, err := ioutil.ReadFile("./data.json")
	if err != nil {
		log.Fatal(err)
	}

	if err := json.Unmarshal(raw, &result); err != nil {
		log.Fatal(err)
	}

	for i := range result {
		result[i].ID = i
	}

	return
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, sessionName)
	people := loadData()
	renderPage(w, r, session, "index.html", people)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, sessionName)
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()["url"]
		url := ""
		if len(q) > 0 {
			url = q[0]
		}
		renderPage(w, r, session, "login.html", map[string]interface{}{"Url": url})
		break
	case http.MethodPost:
		r.ParseForm()
		username := r.Form["username"][0]
		password := r.Form["password"][0]
		url := r.Form["url"][0]
		hasher := md5.New()
		hasher.Write([]byte(username))
		md5password := hex.EncodeToString(hasher.Sum(nil))
		if password == md5password {
			session.Values["username"] = username
			_ = session.Save(r, w)
			redirectURL := "/"
			urlCheckRegex := regexp.MustCompile("^/person/[0-9]+$")
			if urlCheckRegex.MatchString(url) {
				redirectURL = url
			}
			http.Redirect(w, r, redirectURL, 301)
			break
		}
		param := map[string]interface{}{
			"Message":  "Login Error",
			"Username": username,
			"Url":      url,
		}
		w.WriteHeader(401)
		renderPage(w, r, session, "login.html", param)
		break
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, sessionName)
	session.Values["username"] = nil
	_ = session.Save(r, w)
	renderPage(w, r, session, "logout.html", nil)
}

func renderPage(w http.ResponseWriter, r *http.Request, session *sessions.Session, templateFilename string, param interface{}) {
	username := session.Values["username"]
	t, err := template.ParseFiles("template/base.html", "template/"+templateFilename)
	if err != nil {
		log.Fatalf("template error: %v", err)
	}
	params := map[string]interface{}{
		"Username": username,
		"Param":    param,
	}
	w.Header().Set("Content-type", "text/html")
	err = t.Execute(w, params)
	if err != nil {
		log.Printf("failed to execute template: %v", err)
	}
}

func personHandler(w http.ResponseWriter, r *http.Request) {
	i, _ := strconv.Atoi(r.URL.Path[8:])
	var person Person
	session, _ := store.Get(r, sessionName)
	if session.Values["username"] != nil {
		people := loadData()
		person = people[i]
		renderPage(w, r, session, "person.html", person)
	} else {
		w.WriteHeader(403)
		renderPage(w, r, session, "person.html", i)
	}
}

func oauth2AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	u, err := oauth2.CreateAuthorizationRequestURL(exampleScope)
	if err != nil {
		log.Fatal(err)
	}

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func oauth2CallbackHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.FormValue("error"); err != "" {
		log.Printf("error returned from OAuth2 service provider: %v\n", err)
		http.Redirect(w, r, "/oauth2/failure", http.StatusFound)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		log.Println("empty code returned from OAuth2 service provider")
		http.Redirect(w, r, "/oauth2/failure", http.StatusFound)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	token, err := oauth2.ExchangeToken(ctx, code)
	if err != nil {
		log.Printf("failed to exchange OAuth2 code with token: %v\n", err)
		http.Redirect(w, r, "/oauth2/failure", http.StatusFound)
		return
	}

	session, err := store.Get(r, sessionName)
	if err != nil {
		log.Fatal(err)
	}

	// !!! DO NOT STORE TOKEN IN PLAINTEXT IN USER AGENT !!!
	session.Values["oauth2_access_token"] = token.AccessToken
	session.Values["oauth2_expires_in"] = strconv.Itoa(token.ExpiresIn)
	session.Values["oauth2_refresh_token"] = token.RefreshToken
	session.Values["oauth2_scope"] = token.Scope
	session.Values["oauth2_token_type"] = token.TokenType
	err = session.Save(r, w)
	if err != nil {
		log.Printf("error saving session: %v\n", err)
		http.Redirect(w, r, "/oauth2/failure", http.StatusFound)
		return
	}
	// !!! I AM INTENTIONALLY DOING ABOVE FOR THE SAKE OF INSPECTION !!!

	http.Redirect(w, r, "/oauth2/success", http.StatusFound)
}

func oauth2SuccessHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, sessionName)
	if err != nil {
		log.Fatal(err)
	}

	token, err := oauth2.GetTokenFromSession(session)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	user, err := user.RequestUserProfile(token)
	if err != nil {
		log.Printf("failed to get user profile: %v\n", err)
		http.Redirect(w, r, "/oauth2/failure", http.StatusFound)
		return
	}

	renderPage(w, r, session, "oauth2/success.html", user)
}

func oauth2FailureHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, sessionName)
	if err != nil {
		log.Fatal(err)
	}

	renderPage(w, r, session, "oauth2/failure.html", nil)
}

func main() {
	log.Print("SimpleAuthWeb01: starting server...")

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.Handle("/favicon.ico", fs)
	http.HandleFunc("/.well-known/microsoft-identity-association.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "static/microsoft-identity-association.json")
	})
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/person/", personHandler)
	http.HandleFunc("/oauth2/authorize", oauth2AuthorizeHandler)
	http.HandleFunc("/oauth2/callback", oauth2CallbackHandler)
	http.HandleFunc("/oauth2/success", oauth2SuccessHandler)
	http.HandleFunc("/oauth2/failure", oauth2FailureHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("helloworld: listening on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
