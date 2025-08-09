package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
)

func myHandler(w http.ResponseWriter, r *http.Request) {

	// Set Content-Type header
	w.Header().Set("Content-Type", "application/json")
	// Set status code
	w.WriteHeader(http.StatusOK)
	// Write response body
	var myvalue string = r.Header.Get("temperature")

	i, _ := strconv.Atoi(myvalue)
	var st string
	if i > 15 {
		st = "hot"
	} else {
		st = "cold"
	}

	type Employee struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
		City string `json:"city"`
		Temp string `json:"temperature"`
	}
	// sample response json request
	emp := Employee{"John Doe", 30, "London", st}

	if err := json.NewEncoder(w).Encode(emp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func main() {

	var err error
	// Define a simple handler function
	http.HandleFunc("/", myHandler)
	http.HandleFunc("/user", createUserHandler).Methods("POST")
	http.HandleFunc("/user/{id}", getUserHandler).Methods("GET")
	http.HandleFunc("/user/{id}", updateUserHandler).Methods("PUT")
	http.HandleFunc("/user/{id}", deleteUserHandler).Methods("DELETE")

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

	//log.Printf("Starting HTTPS server on :8443 with certificate %s and key %s", certFile, keyFile)

	// Start the HTTPS server
	// The first two arguments are empty strings because the certificate and key are provided
	// directly to the ListenAndServeTLS function.

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert, // Enforce client certificate verification
	}

	var server = &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	//err = http.ListenAndServeTLS(":8443", certFile, keyFile, nil)

	log.Fatal("Teste--", server.ListenAndServeTLS(certFile, keyFile))
}

//https://medium.com/@bytecraze.com/create-an-oauth2-server-in-15-minutes-using-go-a660f6246e61
// https://github.com/go-oauth2/oauth2/blob/master/example/server/server.go
