package controllers

import (
	"../Helpers/X509"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"time"
)

func CertificateCheck(responseWriter http.ResponseWriter, request *http.Request) {
	log.Printf("START at " + time.Now().String())

	certificate, err := helpers.ReadCertificateFromRequest(request)
	if err != nil {
		writeResponse(400, err.Error(), responseWriter)
		return
	}

	abortChannel := make(chan bool)
	defer close(abortChannel)

	verifyCertificateChainChannel := make(chan string)
	defer close(verifyCertificateChainChannel)
	buildTrustChainChannel := make(chan []*x509.Certificate)
	defer close(buildTrustChainChannel)

	go helpers.BuildTrustChain(buildTrustChainChannel, abortChannel, certificate)

	trustChain := <-buildTrustChainChannel
	if len(trustChain) == 1 {
		log.Printf("No parent certificate found. So this is the root certificate. ")
	}

	go helpers.VerifyTrustChain(verifyCertificateChainChannel, trustChain)
	certificateChainErrorMessage := <-verifyCertificateChainChannel
	if certificateChainErrorMessage != "" {
		log.Printf("ABORT Certificate not valid!")
		log.Printf("END at " + time.Now().String())
		writeResponse(400, certificateChainErrorMessage, responseWriter)
		return
	}

	fmt.Fprintf(responseWriter, "Certificate OK ")
}

func writeResponse(statusCode int, message string, responseWriter http.ResponseWriter) {
	responseWriter.WriteHeader(statusCode)
	fmt.Fprintf(responseWriter, message)
}
