package helpers

import (
	"testing"
)

func TestFetchCertificateDataFromUrlWithEmptyUrl(t *testing.T) {
	_, err := fetchCertificateDataFromUrl("")
	if err == nil {
		t.Errorf("Expected an error because url is invalid but got none")
		return
	}

	if err.Error() != "Get \"\": unsupported protocol scheme \"\"" {
		t.Errorf(
			"Expected an error with message: Get \"\": unsupported protocol scheme \"\". Got: %s",
			err.Error(),
		)
	}
}
