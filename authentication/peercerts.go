package authentication

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"sync"
)

type PeerCertMgr struct {
	// Map each peer's qualified name (=CN) to its certificates
	peerCertsByCN   map[string][]*PeerCert
	peerCertsByHash map[CertFingerprint]*PeerCert
	sync.RWMutex

	ManagedCertPool *x509.CertPool
}

// CertRole defines the scope a certificate is valid for
type CertRole uint8

const (
	// Revoked indicates that the referenced certificate is not valid and
	// never wil be again.
	Revoked CertRole = iota
	// Inactive is the default status for a new certificate. It describes
	// that it is currently not used or associated. Therefore, it is not
	// valid for any authentication. Most of the time, this will change
	// later on.
	Inactive
	// Primary indicates this is the primary certificate.
	Primary
	// Backup indicates that all previously declared certs are invalidated.
	// A certificate with this option set allows to replace any of peer's certificates.
	Backup
)

type PeerCert struct {
	Certificate *x509.Certificate `json:"-"`
	Role        CertRole          `json:"certRole"`
}

// NewCertManager creates a new instance to manage our own and peers' certificates
func NewPeerCertMgr() *PeerCertMgr {
	return &PeerCertMgr{
		peerCertsByCN:   make(map[string][]*PeerCert),
		peerCertsByHash: make(map[CertFingerprint]*PeerCert),
		ManagedCertPool: x509.NewCertPool(),
	}
}

func (cm *PeerCertMgr) IsPeerRegistered(cn string) bool {
	cm.RLock()
	defer cm.RUnlock()
	_, exists := cm.peerCertsByCN[cn]
	return exists
}

// AddCert adds a new certificate and associates it with the peer's CN.
//
// If a peer with the same CN exists, it is associated with this peer. The application
// should check before whether a peer exists if this variant is not desired.
func (cm *PeerCertMgr) AddCert(cert *x509.Certificate, role CertRole) (CertFingerprint, error) {
	// Use cert's CommonName and fingerprint for identification
	cn := cert.Subject.CommonName
	fp := Sha256Fingerprint(cert)

	cm.Lock()
	defer cm.Unlock()

	// Check if peer CN is not already in use. We enforce unique CNs for
	// individual peers
	// New: application has to verify a peer's registration before adding
	// a new certificate
	// if _, exists := cm.peerCertsByCN[cn]; exists {
	// 	return "", fmt.Errorf("CertManager: peer with CN '%s' already registered", cn)
	// }
	if _, exists := cm.peerCertsByHash[fp]; exists {
		return "", fmt.Errorf("CertManager: ignore duplicate cert")
	}

	newCert := &PeerCert{
		Certificate: cert,
		Role:        role,
	}
	// Map cert to array of certs associated with the same CN
	cm.peerCertsByCN[cn] = append(cm.peerCertsByCN[cn], newCert)
	// Associate cert with its unique Sha256 fingerprint
	cm.peerCertsByHash[fp] = newCert
	log.Println("Cert fingerprint:", base64.StdEncoding.EncodeToString([]byte(fp)))

	// XXX: temporarily add to CertPool; should require acceptance first
	cm.ManagedCertPool.AddCert(cert)

	// Unique fingerprint for reidentification
	return fp, nil
}

func (cm *PeerCertMgr) UpdateCert(cert *x509.Certificate, role CertRole) {
	fp := Sha256Fingerprint(cert)

	cm.Lock()
	defer cm.Unlock()

	if c, ok := cm.peerCertsByHash[fp]; ok {
		c.Role = role
	}
}

func (cm *PeerCertMgr) RevokeCert(cert *x509.Certificate) {
	fp := Sha256Fingerprint(cert)

	cm.Lock()
	defer cm.Unlock()

	if c, ok := cm.peerCertsByHash[fp]; ok {
		c.Role = Revoked

		// Also invalidate attributes of this certificate so any new TLS
		// connection will fail early
		// Still, it is not necessary due to the gRPC interceptor hook.
		c.Certificate.Raw = nil
		c.Certificate.KeyUsage = 0
		c.Certificate.ExtKeyUsage = []x509.ExtKeyUsage{}
	}
}

func (cm *PeerCertMgr) VerifyPeerIdentity(remote *x509.Certificate) (*PeerCert, error) {
	fp := Sha256Fingerprint(remote)

	cm.RLock()
	defer cm.RUnlock()

	if c, ok := cm.peerCertsByHash[fp]; ok {
		// Check for same Peer ID
		if c.Certificate.Subject.CommonName != remote.Subject.CommonName {
			return nil, fmt.Errorf("CN not matching")
		}
		// Check whether it is an active certificate
		if c.Role <= Inactive {
			return nil, fmt.Errorf("Certificate not active")
		}
		// Further checks should be already done during the TLS handshake.
		// So we can assume that TLS server checks all other fields, e.g. time
		// validity bounds
		return c, nil
	}

	return nil, fmt.Errorf("No matching certificate")
}

func (cm *PeerCertMgr) generateCertPool() {
	pool := x509.NewCertPool()

	cm.RLock()
	defer cm.RUnlock()

	for _, pcs := range cm.peerCertsByCN {
		for _, pc := range pcs {
			pool.AddCert(pc.Certificate)
		}
	}

	// Replace currently used and referenced CertPool. This change is
	// not visible for the current TLS configuration still referencing the
	// previous CertPool instance.
	// TODO: we need to restart the gRPC server in order to take effect.
	cm.ManagedCertPool = pool
}

func (cm *PeerCertMgr) Export() {
	jsonString, err := json.Marshal(cm.peerCertsByHash)
	fmt.Println(string(jsonString), "Err:", err)
}
