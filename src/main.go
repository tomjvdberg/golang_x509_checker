package main

import (
	"./Controllers"
	"log"
	"net/http"
)

const appPort = ":8080"

func main() {
	log.Printf("Server started listening on " + appPort)
	// Register endpoints and their handlers
	http.HandleFunc("/", controllers.CertificateCheck)

	// Start the server
	log.Fatal(http.ListenAndServe(appPort, nil))
}
