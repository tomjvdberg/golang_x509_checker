package main

import (
	"./Controllers"
	"./Middleware"
	"log"
	"net/http"
)

const appPort = ":8080"

func main() {
	log.Printf("Server started listening on " + appPort)
	mux := http.NewServeMux()

	// create handlers
	certificateCheckHandler := http.HandlerFunc(controllers.CertificateCheck)

	// Match endpoints to handlers
	mux.Handle("/", middleware.RequestHandleTimer(certificateCheckHandler))

	// Start the server
	log.Fatal(http.ListenAndServe(appPort, mux))
}
