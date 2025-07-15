package main

import (
	handler "jwt-auth-server/internal/auth"
	"net/http"
)

func main() {
	http.HandleFunc("/login", handler.LoginHandler)
	http.HandleFunc("/protected", handler.ProtectedHandler)

	http.ListenAndServe(":8080", nil)
}
