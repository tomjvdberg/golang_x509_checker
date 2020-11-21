package controllers

import (
	"../Helpers/X509"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func CertificateCheck(responseWriter http.ResponseWriter, request *http.Request) {
	log.Printf("START at " + time.Now().String())

	certificatePemData, err := readCertificateFromBody(request)
	if err != nil {
		writeResponse(400, err.Error(), responseWriter)
		return
	}

	certificate, err := parseCertificatePEMData(certificatePemData)
	if err != nil {
		writeResponse(400, err.Error(), responseWriter)
		return
	}

	abortChannel := make(chan bool)
	defer close(abortChannel)

	checkCertificateChannel := make(chan bool)
	defer close(checkCertificateChannel)
	getParentCertificateChannel := make(chan string)
	defer close(getParentCertificateChannel)

	go helpers.CheckCertificate(checkCertificateChannel, certificate)
	go helpers.FetchCertificateFromUrl(getParentCertificateChannel, abortChannel, certificate)

	certificateIsValid := <-checkCertificateChannel
	if !certificateIsValid {
		log.Printf("ABORT Certificate not valid!")
		abortChannel <- true
		log.Printf("END at " + time.Now().String())
		writeResponse(400, "certificate is not valid", responseWriter)
		return
	}

	parentCertificate := <-getParentCertificateChannel
	if parentCertificate == "" {
		log.Printf("No parent certificate found. So this is the root certificate. ")
	}

	abortChannel <- true

	fmt.Fprintf(responseWriter, "Certificate OK ")
}

func writeResponse(statusCode int, message string, responseWriter http.ResponseWriter) {
	responseWriter.WriteHeader(statusCode)
	fmt.Fprintf(responseWriter, message)
}

func readCertificateFromBody(request *http.Request) (certificatePEMData []byte, err error) {
	certificatePemData, err := ioutil.ReadAll(request.Body)

	if err != nil || len(certificatePemData) == 0 {
		return nil, errors.New("Invalid body provided")
	}

	return certificatePemData, nil
}

func parseCertificatePEMData(certificatePemData []byte) (certificate *x509.Certificate, err error) {
	block, _ := pem.Decode(certificatePemData)
	if block == nil {
		return nil, errors.New("Invalid block")
	}

	certificate, err = x509.ParseCertificate(block.Bytes)

	if err != nil || certificate == nil {
		return nil, errors.New("Could not parse the certificate")
	}

	return certificate, nil
}
