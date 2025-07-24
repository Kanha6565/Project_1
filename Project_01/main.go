package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
)

type User struct {
	Username string
	Password string
}

var users = map[string]User{}

var sessions = map[string]string{}

func main() {
	http.HandleFunc("/", serveLoginPage)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/logout", logoutHandler)

	fmt.Println("🚀 Server running at http://localhost:8000")
	http.ListenAndServe(":8000", nil)
}
func serveLoginPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/signup")
}
func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "static/signup.html")
		return
	}

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Form error", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")

		if _, exists := users[username]; exists {
			http.Error(w, "Username already taken", http.StatusBadRequest)
			return
		}

		if password != confirm {
			http.Error(w, "Passwords do not match", http.StatusBadRequest)
			return
		}

		users[username] = User{Username: username, Password: password}
		fmt.Println("User registered:", username)

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Form parse error", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, exists := users[username]
	if !exists || user.Password != password {
		http.ServeFile(w, r, "static/error.html")
		return
	}

	sessionID, err := generateSessionID()
	if err != nil {
		http.Error(w, "Session creation error", http.StatusInternalServerError)
		return
	}
	sessions[sessionID] = username

	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: sessionID,
		Path:  "/",
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil || sessions[cookie.Value] == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := sessions[cookie.Value]
	fmt.Printf(" %s accessed dashboard\n", username)
	http.ServeFile(w, r, "static/dashboard.html")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		delete(sessions, cookie.Value)
		http.SetCookie(w, &http.Cookie{
			Name:   "session",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
