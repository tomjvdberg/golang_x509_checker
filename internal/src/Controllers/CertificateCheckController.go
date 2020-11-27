package controllers

import (
	"../Helpers/X509"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type CertificateCheckRequest struct {
	SubjectCertificate string
	Truststore         string
	ReferenceTime      time.Time
}

func CertificateCheck(responseWriter http.ResponseWriter, request *http.Request) {
	certificateRequest, err := parseRequestToJson(request)
	if err != nil {
		http.Error(responseWriter, err.Error(), http.StatusBadRequest)
		return
	}

	certificate, err := helpers.ParseCertificatePEMData([]byte(certificateRequest.SubjectCertificate))
	if err != nil {
		http.Error(responseWriter, err.Error(), http.StatusBadRequest)
		return
	}

	verifyCertificateChainChannel := make(chan error)
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
	certificateChainError := <-verifyCertificateChainChannel
	if certificateChainError != nil {
		http.Error(responseWriter, certificateChainError.Error(), http.StatusBadRequest)
		return
	}

	responseWriter.WriteHeader(http.StatusNoContent)
}

func parseRequestToJson(request *http.Request) (certificateCheckRequest CertificateCheckRequest, err error) {
	defer request.Body.Close()
	requestJson, err := ioutil.ReadAll(request.Body)
	if err != nil || len(requestJson) == 0 {
		return certificateCheckRequest, errors.New("invalid body provided")
	}

	err = json.Unmarshal(requestJson, &certificateCheckRequest)
	if err != nil {
		return certificateCheckRequest, errors.New("JSON format error: " + err.Error())
	}

	return certificateCheckRequest, err
}
