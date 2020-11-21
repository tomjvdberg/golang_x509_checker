package helpers

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
)

const rootPEM = `
-----BEGIN CERTIFICATE-----
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
LwcjiBr0Kg==
-----END CERTIFICATE-----`

const intermediatePEM = `
-----BEGIN CERTIFICATE-----
MIIEpjCCAo4CFALq9QbNuDYz17bCNbICotVICss3MA0GCSqGSIb3DQEBCwUAMHkx
CzAJBgNVBAYTAk5MMRAwDgYDVQQIDAdVdHJlY2h0MQ4wDAYDVQQHDAVEb29ybjEP
MA0GA1UECgwGU3l2ZW50MRIwEAYDVQQDDAlzeXZlbnQubmwxIzAhBgkqhkiG9w0B
CQEWFHZhbmRlbmJlcmdAc3l2ZW50Lm5sMB4XDTIwMTEyMDA4MDM0OFoXDTIyMDQw
NDA4MDM0OFowgaUxCzAJBgNVBAYTAk5MMRAwDgYDVQQIDAdVdHJlY2h0MRAwDgYD
VQQHDAdMZWVyc3VtMSEwHwYDVQQKDBhJbnRlcm1lZGlhdGUgZnJvbSBTeXZlbnQx
ETAPBgNVBAsMCFNlY3VyaXR5MRUwEwYDVQQDDAxJbnRlcm1lZGlhdGUxJTAjBgkq
hkiG9w0BCQEWFmludGVybWVkaWF0ZUBzeXZlbnQubmwwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCsEp2Zy9+KxsGbzxpziYwFB+J9fFhFnl/K5sVRCTSI
8o01UrL16Cwib2Ogi7fDCDZY69AGHOXae/Cc9FhQMhQqTHmGBJ9GsePj1defWrNL
qJjqqrWU0LtuMfkPLvQZBa1KSAvKc2x3KHB02EMnxSQ5G3sOpcsM+0u/t8InEH30
lO9kDAflrOEsGJRlHqvq5OxopOJMrQtrfmiKu0wvEppFhvg6lyKSW309aLMgtIf+
F3J5Bsr2sIeUesNVNM75XllCKJyOAq3IpkXPObu70bc1AnPUPE+t8PuNl3bKVsb1
EL7RcjjjcWn2R5r81WTWrpsLwLoYhMnEna7i8jB59hQxAgMBAAEwDQYJKoZIhvcN
AQELBQADggIBAI7hSJmWfqFP2/5rMSSTfLbpDne/M0LlN28ThieUW9jt3/ydvkD9
r9vp12uCkjxNmLZXoTgxqW9hsOfQ0ZL3HYh6OV0KIGBigVouDYArhJXboiTlW5Hk
x+sCYR1LDzocTs1Inu85+fWUDrRlN5AlUdqrSRlzJSLLKdbqkUMh0uxRrM4qzCZN
lKDu8BO3qJ/8oOAvqQeteJniGtvrUVH0962/Hf6HE5vskNyCRDFwxdignz5eFziY
UyHnUyS6eXpZRW/7PzSYPN73MUrrvuU12JMDvc69yI6Lw7N2Qa5R5v/z/8jIz1VH
wVjK6HvX+bsSxuBbwLeS13BfmUWmc1oyd66+J1iPIeN194t92C/igq2mgJJyNHHb
LgJ64xURLGt6PgqHbsTkEVKGeq/JQ/Q1LeRpCknv5P8c/QaudHo0Pi1xUpIU4GLr
ApkOZXk2nyyQ3F+13RgcBQOZXzI2PIsohy5RVayxZqr5oLbLBkcZv0o8YkDnCuaH
vF8e6cwL2s1vhDWRJAvnF13/t51Ux/eWtRDqFzKMkFGzq9tmHmoKwEQV24mCZqZa
qv4a19E97jCVv/to50FaUz5uoQWzAQDMmA3jcQU7TGVYYNFBtYL5PSUoF6tzo88g
jbhYDECcGLPKm+8Ll5DXHkl6uh4GCjLPWb+s1c1vJzLA1nMH8aKSo+Iq
-----END CERTIFICATE-----`

func BuildTrustChain(channel chan []*x509.Certificate, abortChannel <-chan bool, certificate *x509.Certificate) {
	log.Printf("Building trust chain")
	trustChain := []*x509.Certificate{}
	trustChain = append(trustChain, certificate)

	// TODO loop while parentURL is not NULL
	parentUrl := certificate.IssuingCertificateURL
	if len(parentUrl) > 0 && len(parentUrl[0]) > 0 {
		log.Print(parentUrl[0])
		resp, err := http.Get(parentUrl[0])

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

			trustChain = append(trustChain, newCert)
		}

		if err != nil {
			log.Printf(err.Error())
		}

	} else {
		log.Printf("No parent certificate URL found")
	}

	select {
	case <-abortChannel:
		log.Printf("Fetching parent certificate ABORTED!")
		return
	default:
		channel <- trustChain
	}
}

func VerifyTrustChain(channel chan string, trustChain []*x509.Certificate) {
	rootCertificates := x509.NewCertPool()
	intermediateCertificates := x509.NewCertPool()

	log.Printf("Checking certificate")
	log.Print(trustChain)
	subjectCertificate := trustChain[0] // the first cert is the subject

	myCa, _ := ParseCertificatePEMData([]byte(rootPEM))
	rootCertificates.AddCert(myCa) // add you CA's
	rootCertificates.AddCert(myCa) // add you CA's

	myCaIntermediate, _ := ParseCertificatePEMData([]byte(intermediatePEM))
	intermediateCertificates.AddCert(myCa)             // add you CA's intermediates
	intermediateCertificates.AddCert(myCaIntermediate) // add you CA's intermediates
	//intermediateCertificates.AddCert(myCaIntermediate) // add you CA's intermediates

	if len(trustChain) > 1 {
		rootCertificates.AddCert(trustChain[len(trustChain)-1]) // the last cert is the root. This may be the same cert
	}

	if len(trustChain) > 2 {
		for _, intermediateCertificate := range trustChain[1 : len(trustChain)-2] {
			intermediateCertificates.AddCert(intermediateCertificate)
		}
	}

	verifyOptions := x509.VerifyOptions{
		Roots:         rootCertificates,
		Intermediates: intermediateCertificates,
	}
	_, err := subjectCertificate.Verify(verifyOptions)

	if err != nil {
		log.Printf(err.Error())
		channel <- err.Error()
		return
	}

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

func ParseCertificatePEMData(certificatePemData []byte) (certificate *x509.Certificate, err error) {
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
