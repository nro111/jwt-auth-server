package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var mySecret = []byte("supersecret")

// This authenticates users and returns a token on success
func loginHandler(w http.ResponseWriter, r *http.Request) {

	// What to look for in the json data sent in via r.Body
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Decode r.Body using the string patterns in creds
	json.NewDecoder(r.Body).Decode(&creds)

	// Fail fast and return an unauthorized error to the client
	if creds.Username != "admin" || creds.Password != "password" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Create a new jwt token with a specific signing method and a set of claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": creds.Username,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	// Use the secret key to sign the token previously generated
	tokenStr, err := token.SignedString(mySecret)

	// Fail fast if theres an error. Return a 500 status to the client
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Write to the response stream w with the token as a response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenStr})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// Get Authorization from the request header
	auth := r.Header.Get("Authorization")

	// Fail fast if auth is missing or non existent. Return an unauthorized error
	if auth == "" {
		http.Error(w, "missing auth", http.StatusUnauthorized)
		return
	}

	// Parse auth for the string Bearer
	tokenStr := auth[len("Bearer "):]

	// Parse the token string to get the actual token
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return mySecret, nil
	})

	// Fail if theres an error or if the token isnt value. Send back a 401 error to the client.
	if err != nil || !token.Valid {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	w.Write([]byte("protected content"))
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/protected", protectedHandler)

	http.ListenAndServe(":8080", nil)
}
