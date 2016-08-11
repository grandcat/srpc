package authentication

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

type CertFingerprint string

func Sha256Fingerprint(cert *x509.Certificate) CertFingerprint {
	rawFp := sha256.Sum256(cert.RawSubjectPublicKeyInfo)

	// Go1.6 MarshalJSON does not support a custom implementation for a map[key].
	// It only supports strings that are taken directly without checking for custom
	// marshal implementations.
	// Go1.7 will fix it:
	// https://github.com/golang/go/commit/ffbd31e9f79ad8b6aaeceac1397678e237581064
	// Meanwhile, we encode the (non-ASCII) string here as Base64. This might be
	// slightly less efficient.

	return CertFingerprint(base64.StdEncoding.EncodeToString(rawFp[:]))
}

// func (fp CertFingerprint) MarshalJSON() ([]byte, error) {
// 	return json.Marshal(base64.StdEncoding.EncodeToString([]byte(fp)))
// }

// func (fp *CertFingerprint) UnmarshalJSON(data []byte) error {
// 	var t string
// 	if err := json.Unmarshal(data, &t); err != nil {
// 		return fmt.Errorf("deocde secret string: %v", err)
// 	}

// 	rawFp, err := base64.StdEncoding.DecodeString(t)
// 	if err != nil {
// 		return err
// 	}

// 	*fp = CertFingerprint(rawFp)
// 	return nil
// }
