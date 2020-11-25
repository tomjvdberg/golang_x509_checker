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

func BuildTrustChain(
	channel chan []*x509.Certificate,
	certificate *x509.Certificate,
) {

	log.Printf("Building trust chain")
	trustChain := []*x509.Certificate{}
	trustChain = append(trustChain, certificate)

	parentUrl := certificate.IssuingCertificateURL
	maxLoops := 5 // TODO make constant
	loopCounter := 0
	for {
		if len(parentUrl) == 0 || len(parentUrl[0]) == 0 {
			log.Printf("No parent certificate URL found")
			break
		}

		newCert, err := getCertificateFromUrl(parentUrl[0])
		if err == nil {
			log.Printf("Adding retrieved parent certificate.")
			trustChain = append(trustChain, newCert)
		}

		if newCert == nil {
			log.Printf("No certificate found? ??")
			break
		}

		if loopCounter > maxLoops {
			log.Printf("Maximum length of trustchain reached. Breaking.")
			break
		}

		parentUrl = newCert.IssuingCertificateURL
		loopCounter++
	}

	channel <- trustChain
}

func VerifyTrustChain(
	channel chan string,
	trustChain []*x509.Certificate,
	certsFromPEM []byte,
	verificationReferenceTime time.Time,
) {
	rootCertificates := x509.NewCertPool()
	intermediateCertificates := x509.NewCertPool()

	log.Printf("Verifying trust chain")
	subjectCertificate := trustChain[0] // the first cert is the subject

	/* Add your CA's as root authority*/
	ok := rootCertificates.AppendCertsFromPEM(certsFromPEM) // add your CA's
	if !ok {
		channel <- "error appending roots from PEM"
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
		// set a time to verify in the past
		CurrentTime: verificationReferenceTime,
	}
	_, err := subjectCertificate.Verify(verifyOptions)
	if err != nil {
		log.Printf(err.Error())
		channel <- err.Error()
		return
	}

	// TODO return error or nil instead of error message
	channel <- "" // return if the certificate is found to be valid
}

func ReadCertificateFromRequest(request *http.Request) (certificate *x509.Certificate, err error) {
	certificatePemData, err := ioutil.ReadAll(request.Body)

	if err != nil || len(certificatePemData) == 0 {
		return nil, errors.New("Invalid body provided")
	}

	certificate, err = ParseCertificatePEMData(certificatePemData)

	return certificate, err
}

func getCertificateFromUrl(certificateUrl string) (certificate *x509.Certificate, err error) {
	resp, err := http.Get(certificateUrl)

	if resp != nil {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf(err.Error())
		}

		newCert, err := x509.ParseCertificate(body)
		if err != nil {
			log.Printf(err.Error())
		}

		return newCert, err
	}

	if err != nil {
		log.Printf(err.Error())
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
