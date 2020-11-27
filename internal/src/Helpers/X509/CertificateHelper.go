package helpers

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

const maxStepsToRootCertificate = 5

func BuildTrustChain(
	channel chan []*x509.Certificate,
	certificate *x509.Certificate,
) {
	log.Printf("Building trust chain")
	trustChain := []*x509.Certificate{}
	trustChain = append(trustChain, certificate)

	parentUrl := certificate.IssuingCertificateURL
	loopCounter := 0
	for {
		if len(parentUrl) == 0 || len(parentUrl[0]) == 0 {
			log.Printf("No parent certificate URL found")
			break
		}

		certificateData, err := fetchCertificateDataFromUrl(parentUrl[0])
		if err != nil {
			log.Printf(err.Error())
			break
		}

		newCert, err := x509.ParseCertificate(certificateData)
		if err == nil {
			log.Printf("Adding retrieved parent certificate.")
			trustChain = append(trustChain, newCert)
		}

		if newCert == nil {
			log.Printf("No certificate found? ??")
			break
		}

		if loopCounter >= maxStepsToRootCertificate {
			log.Printf("Maximum length of trustchain reached. Breaking.")
			break
		}

		parentUrl = newCert.IssuingCertificateURL
		loopCounter++
	}

	channel <- trustChain
}

func VerifyTrustChain(
	channel chan error,
	trustChain []*x509.Certificate,
	certsFromPEM []byte,
	verificationReferenceTime time.Time,
) {
	rootCertificates := x509.NewCertPool()
	intermediateCertificates := x509.NewCertPool()

	log.Printf("Verifying trust chain")
	subjectCertificate := trustChain[0] // the first cert is the subject

	// Add your CA's as root authority
	ok := rootCertificates.AppendCertsFromPEM(certsFromPEM) // add your CA's
	if !ok {
		channel <- errors.New("error appending roots from PEM")
		return
	}

	if len(trustChain) > 1 {
		for _, intermediateCertificate := range trustChain[1:] {
			intermediateCertificates.AddCert(intermediateCertificate)
		}
	}

	verifyOptions := x509.VerifyOptions{
		Roots:         rootCertificates,         // The CA's
		Intermediates: intermediateCertificates, // all parent certificates from the subject certificate
		// allows to verify is a certificate was valid in the past
		CurrentTime: verificationReferenceTime,
	}

	_, err := subjectCertificate.Verify(verifyOptions)
	if err != nil {
		channel <- err
		return
	}

	channel <- nil // no error found. Certificate is valid.
}

func fetchCertificateDataFromUrl(certificateUrl string) ([]byte, error) {
	resp, err := http.Get(certificateUrl)

	if resp != nil {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf(err.Error())
			return nil, err
		}

		return body, err
	}

	return nil, err
}

func ParseCertificatePEMData(certificatePemData []byte) (certificate *x509.Certificate, err error) {
	block, _ := pem.Decode(certificatePemData)
	if block == nil {
		return nil, errors.New("Invalid block")
	}

	return blockToCertificate(block)
}

func blockToCertificate(block *pem.Block) (certificate *x509.Certificate, err error) {
	certificate, err = x509.ParseCertificate(block.Bytes)

	if err != nil || certificate == nil {
		return nil, errors.New("Could not parse the certificate")
	}

	return certificate, nil
}
