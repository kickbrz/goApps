package main

import (
	"apiserver-jwt-mysql/db"
	handlers "apiserver-jwt-mysql/hdl"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func main() {

	var err error

	database, err := db.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Define a simple handler function
	r := mux.NewRouter()

	// Endpoint

	r.HandleFunc("/register", handlers.CreateUser(database)).Methods("POST")
	r.HandleFunc("/login", handlers.LoginHandler(database)).Methods("POST")

	r.HandleFunc("/users", handlers.AuthMiddleware(handlers.GetUsers(database))).Methods("GET")
	r.HandleFunc("/users/{id:[0-9]+}", handlers.AuthMiddleware(handlers.UpdateUser(database))).Methods("PUT")
	r.HandleFunc("/users/{id:[0-9]+}", handlers.AuthMiddleware(handlers.DeleteUser(database))).Methods("DELETE")

	// Specify servers certifcate files
	// Replace "server.crt" and "server.key" with your actual certificate and key file paths
	certFile := "server.crt"
	keyFile := "server.key"

	// client certicate
	caCert, err := os.ReadFile("client.crt")
	if err != nil {
		log.Printf("Not read client certificate")
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert, // Enforce client certificate verification
	}

	var server = &http.Server{
		Addr:      ":8443",
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	//err = http.ListenAndServeTLS(":8443", certFile, keyFile, nil)

	log.Fatal("Running Middleware", server.ListenAndServeTLS(certFile, keyFile))
}
