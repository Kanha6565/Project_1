package main

import (
	"fmt"
	"net/http"
	"time"
)

type Login struct {
	HashedPassword string
	SessionToken   string
	CREFToken      string
}

// Key is the username
var users = map[string]Login{}

func main() {
	http.HandleFunc("/resister", resister)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.ListenAndServe(":8080", nil)
}

func resister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invialid Method", er)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	conformpassword := r.FormValue("conformpassword")
	if len(username) < 8 || len(password) < 8 {
		er := http.StatusNotAcceptable
		http.Error(w, "Invilid usernanme/password\nEnter with in 7 Character", er)
		return
	}
	if password != conformpassword {
		er := http.StatusNotAcceptable
		http.Error(w, "Not matching with your password", er)
		return
	}
	if _, ok := users[username]; ok {
		er := http.StatusConflict
		http.Error(w, "User alreday exists", er)
		return
	}
	hashedPassword, _ := hashedPassword(password)
	users[username] = Login{
		HashedPassword: hashedPassword,
	}
	fmt.Fprintln(w, "User registered successfully!")

}
func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invialid Method", er)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	user, ok := users[username]
	if !ok || !checkPasswordHash(password, user.HashedPassword) {
		er := http.StatusUnauthorized
		http.Error(w, "Invild username or password", er)
		return
	}
	//Set session cookie
	sessionToken := generateToken(32)
	csrfToken := generateToken((32))

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	//Set CSRF token in a cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false, //Needs to be accessiblw to the client-side
	})
	//Store token in the database
	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user
	fmt.Fprintln(w, "Login sucessful!")
}
func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invialid Method", er)
		return
	}

	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return

	}
	username := r.FormValue("username")
	fmt.Fprintln(w, "CSRF validition sucesful! Welcome,%s", username)

}
func protected(w http.ResponseWriter, r *http.Request) {
	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return

	}
	//Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	//Set CSRF token in a cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false, //Needs to be accessiblw to the client-side
	})

	//Clear the token fram the database
	username := r.FormValue("username")
	user, _ := users[username]
	user.SessionToken = ""
	user.CSRFToken = ""
	users[username] = user

	fmt.Fprintln(w, "Logged out sucessfully!")
}
