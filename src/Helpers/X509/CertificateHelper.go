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

const rootPEM = `
-----BEGIN CERTIFICATE-----
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
LwcjiBr0Kg==
-----END CERTIFICATE-----`

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

	certificate, err = parseCertificatePEMData(certificatePemData)

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

func parseCertificatePEMData(certificatePemData []byte) (certificate *x509.Certificate, err error) {
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
