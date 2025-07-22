package main

import (
	"net/http"
)

var AuthError = error.New("Unauthorizrd")

func Autorize(r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		return AuthError
	}
	st, err := r.Cookie("sessiom-token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return AuthError
	}
	//Get the csrf token from the heaaers
	csrf := r.Heder.GEt("X-CSRF-TOKEn")
	if csrf != user.CSRFToken || csrf == "" {
		return AuthError
	}
	return nil
}
