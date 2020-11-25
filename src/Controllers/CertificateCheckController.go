package controllers

import (
	"../Helpers/X509"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"
)

type CertificateCheckRequest struct {
	SubjectCertificate string
	Truststore         string
	ReferenceTime      time.Time
}

func CertificateCheck(responseWriter http.ResponseWriter, request *http.Request) {
	log.Printf("START at " + strconv.Itoa(int(time.Now().UnixNano())))

	var certificateRequest CertificateCheckRequest

	requestJson, err := ioutil.ReadAll(request.Body)
	if err != nil || len(requestJson) == 0 {
		writeResponse(400, "Invalid body provided", responseWriter)
		return
	}

	err = json.Unmarshal(requestJson, &certificateRequest)
	if err != nil {
		log.Printf("Json format error")
		writeResponse(400, err.Error(), responseWriter)
		return
	}

	certificate, err := helpers.ParseCertificatePEMData([]byte(certificateRequest.SubjectCertificate))
	if err != nil {
		writeResponse(400, err.Error(), responseWriter)
		return
	}

	verifyCertificateChainChannel := make(chan string)
	buildTrustChainChannel := make(chan []*x509.Certificate)

	defer close(verifyCertificateChainChannel)
	defer close(buildTrustChainChannel)

	go helpers.BuildTrustChain(buildTrustChainChannel, certificate)
	trustChain := <-buildTrustChainChannel
	if len(trustChain) == 1 {
		log.Printf("No parent certificate found. So this is the root certificate. ")
	}

	go helpers.VerifyTrustChain(
		verifyCertificateChainChannel,
		trustChain,
		[]byte(certificateRequest.Truststore),
		certificateRequest.ReferenceTime,
	)
	certificateChainErrorMessage := <-verifyCertificateChainChannel
	if certificateChainErrorMessage != "" {
		log.Printf("ABORT Certificate not valid!")
		log.Printf("END at " + strconv.Itoa(int(time.Now().UnixNano())))
		writeResponse(400, certificateChainErrorMessage, responseWriter)
		return
	}

	log.Printf("END at " + strconv.Itoa(int(time.Now().UnixNano())))
	fmt.Fprintf(responseWriter, "Certificate OK ")
}

func writeResponse(statusCode int, message string, responseWriter http.ResponseWriter) {
	responseWriter.WriteHeader(statusCode)
	fmt.Fprintf(responseWriter, message)
}
