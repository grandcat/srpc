package common

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

// ReadCertFromPEM reads a PEM file from disk and converts it to the internal
// Certificate data structure
// Note: this functions is largely borrowed from x509.AppendCertsFromPEM()
func ReadCertFromPEM(filename string) (*x509.Certificate, error) {
	clientCertStream, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c, _, err := ParseCertFromPEMBytes(clientCertStream)
	return c, err
}

var ErrUnsupportedPEM = errors.New("Invalid certificate header")

func ParseCertFromPEMBytes(pemBlock []byte) (c *x509.Certificate, rest []byte, err error) {
	// Fetch first block from PEM file
	var block *pem.Block
	block, rest = pem.Decode(pemBlock)
	if block == nil {
		return nil, nil, fmt.Errorf("Invalid PEM block")
	}
	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, nil, ErrUnsupportedPEM
	}

	c, err = x509.ParseCertificate(block.Bytes)
	return
}
