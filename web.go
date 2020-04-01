package main

import (
	"log"
	"net/http"
)

// indexHandler provides links to login, logout, and to visit the "me" page.
func (s *service) indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<div><a href="/login">Login</a></div>`))
	w.Write([]byte(`<div><a href="/me">Me</a></div>`))
	w.Write([]byte(`<div><a href="/logout">Logout</a></div>`))
}

// meHandler prints either the user's email address or "no user"
// based on whether the user is logged in.
func (s *service) meHandler(w http.ResponseWriter, r *http.Request) {
	user, err := s.currentUser(r)
	if err == ErrNoUser {
		w.Write([]byte("no user"))
		return
	}
	if err != nil {
		log.Printf("failed to get current user: %s", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Write([]byte(user.Email))
}
