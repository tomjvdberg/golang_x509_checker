package helpers

import (
	"crypto/x509"
	"testing"
)

const validPEMBlock = `
-----BEGIN CERTIFICATE-----
MIIDvjCCAqYCFHRh1xqqrWUXM3SdapeZpw8U+1WUMA0GCSqGSIb3DQEBCwUAMIGl
MQswCQYDVQQGEwJOTDEQMA4GA1UECAwHVXRyZWNodDEQMA4GA1UEBwwHTGVlcnN1
bTEhMB8GA1UECgwYSW50ZXJtZWRpYXRlIGZyb20gU3l2ZW50MREwDwYDVQQLDAhT
ZWN1cml0eTEVMBMGA1UEAwwMSW50ZXJtZWRpYXRlMSUwIwYJKoZIhvcNAQkBFhZp
bnRlcm1lZGlhdGVAc3l2ZW50Lm5sMB4XDTIwMTEyMDA4MDkxNVoXDTIxMDcyODA4
MDkxNVowgZAxCzAJBgNVBAYTAk5MMRAwDgYDVQQIDAdVdHJlY2h0MQ4wDAYDVQQH
DAVNYWFybjEWMBQGA1UECgwNQ2xpZW50IFN5dmVudDEOMAwGA1UECwwFVXNlcnMx
FjAUBgNVBAMMDWNsaWVudC5zeXZlbnQxHzAdBgkqhkiG9w0BCQEWEGNsaWVudEBz
eXZlbnQubmwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDR2pmbuNe3
eeqSLWjkEEjw+2ZZz8yn9jHoYAsGCb2Vu0kgGPlSkR5vGXpdU7occCHjdF2XKT6R
eXqOmolH1Rh7mTALNAUKO18vNkIAfu0D2u5K1JQkllscd13OSLbtY9Kd+R4EDCnb
+OQ/Xs6mh4FEieV88UvoM/EBHDisf6XVNOqgPzsVFQugxqZmKw6UBoZvjDCYtgGU
phNy/Bpj6qHX7snLr51r4nCJEKXIytrAAFmRhrBhexQnkZFTXrpFUUlWKzAQSFIO
AqXjZK2hTOnm+TK9xDywYKCjCsZN8TMKRT6R8CWGSprKQqCMvFPLPPuYXJFfeuMv
ZvhqUkhfKvZHAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAH93aLeENQNn04/vjNmi
GLK6WJ3oJFNzlfyUR9gWmdEiD81KVktDbN8BqMoevEE7ck6jbpyw4byPHxUEV+dG
wixYxRv+5JDqPyhvHySnpiG+/yUET16X/6e6vv4+d60mlawJO9uq+ldBCofdw7mQ
KH2L8KoRzAISNyABT873pQJesmD0Ra9dIDJ/APyegs3wF0KtDd0VWFe3p31dEqcn
60xmEu9e1R/xnTPuUGGbx+4px9XOH6ebjnPOGtyZwl8bv52qQRt+lxS0XnwC5SHP
mLU1HQH3CSrbZ/hRgg8Ozv8e1qnBmKyGBBwkxhRrNjqHav+jg1wXzettLB6W1R4S
01c=
-----END CERTIFICATE-----
`

func TestBuildTrustChainWithoutParentCertificateUrl(t *testing.T) {
	resultChannel := make(chan []*x509.Certificate)

	certificate, err := ParseCertificatePEMData([]byte(validPEMBlock))

	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	go BuildTrustChain(resultChannel, certificate)

	trustChain := <-resultChannel

	if len(trustChain) == 0 || len(trustChain) > 1 {
		t.Errorf("Expected the trustChain to hold exactly one item. Got: %d", len(trustChain))
	}
}

// TODO make test to build chain when there is a parent url. Need to make a mock HTTP client for that.
