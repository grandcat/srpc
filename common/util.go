package common

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// ReadCertFromPEM reads a PEM file from disk and converts it to the internal
// Certificate data structure
// Note: this functions is largely based on x509.AppendCertsFromPEM()
func ReadCertFromPEM(filename string) (*x509.Certificate, error) {
	clientCertStream, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	// Fetch first block from PEM file
	var block *pem.Block
	block, _ = pem.Decode(clientCertStream)
	if block == nil {
		return nil, fmt.Errorf("Invalid PEM block")
	}
	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, fmt.Errorf("Invalid certificate header")
	}

	return x509.ParseCertificate(block.Bytes)
}
