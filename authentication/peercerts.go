package authentication

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"

	util "github.com/grandcat/flexsmc/common"
)

type PeerCertMgr struct {
	// Map each peer's qualified name (=CN) to its certificates
	peerCertsByCN   map[string][]*PeerCert
	peerCertsByHash map[CertFingerprint]*PeerCert
	mu              sync.RWMutex

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
	cm.mu.RLock()
	defer cm.mu.RUnlock()
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

	cm.mu.Lock()
	defer cm.mu.Unlock()

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
	log.Println("Cert fingerprint:", fp)

	// XXX: temporarily add to CertPool; should require acceptance first
	cm.ManagedCertPool.AddCert(cert)

	// Unique fingerprint for reidentification
	return fp, nil
}

func (cm *PeerCertMgr) UpdateCert(cert *x509.Certificate, role CertRole) {
	fp := Sha256Fingerprint(cert)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if c, ok := cm.peerCertsByHash[fp]; ok {
		c.Role = role
	}
}

func (cm *PeerCertMgr) RevokeCert(cert *x509.Certificate) {
	fp := Sha256Fingerprint(cert)

	cm.mu.Lock()
	defer cm.mu.Unlock()

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

	cm.mu.RLock()
	defer cm.mu.RUnlock()

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

	cm.mu.RLock()
	defer cm.mu.RUnlock()

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

func (cm *PeerCertMgr) LoadFromPath(dirpath string) error {
	// Extract base path
	dirpath = filepath.Dir(dirpath) + string(os.PathSeparator)
	// Load meta data
	// Based on that, we decide which certificates are valid to be kept in memory
	js, err := ioutil.ReadFile(dirpath + "peer_certificates.meta.json")
	if err != nil {
		return err
	}

	var managedCerts map[CertFingerprint]*PeerCert
	err = json.Unmarshal(js, &managedCerts)
	if err != nil {
		return err
	}

	// Load all certificates from PEM file. Based on the meta information, we
	// decide to keep it or reject it
	pemCerts, err := ioutil.ReadFile(dirpath + "peer_certificates.pem")
	if err != nil {
		return err
	}

	for len(pemCerts) > 0 {
		var c *x509.Certificate
		c, pemCerts, err = util.ParseCertFromPEMBytes(pemCerts)
		if err != nil {
			if err == util.ErrUnsupportedPEM {
				// Skip unknown PEM encodings other than CERTIFICATE
				continue
			}
			return fmt.Errorf("LoadFromPath: %v", err)
		}

		// Only add certificate if it is part of the directory (meta file)
		if meta, exists := managedCerts[Sha256Fingerprint(c)]; exists {
			cm.AddCert(c, meta.Role)
		} else {
			fmt.Errorf("Skipping certificate %s. Not part of meta file.\n",
				Sha256Fingerprint(c))
		}
	}

	return nil
}

func (cm *PeerCertMgr) StoreToPath(dirpath string) error {
	// Extract base path
	dirpath = filepath.Dir(dirpath) + string(os.PathSeparator)

	// Write metadata for all managed peer certificates
	js, err := json.Marshal(cm.peerCertsByHash)
	if err != nil {
		return fmt.Errorf("StoreToPath: %v", err)
	}
	ioutil.WriteFile(dirpath+"peer_certificates.meta.json", js, 0644)

	// Write all certificates to a common PEM encoded file
	log.Println("Exporting all certificates from peer cert pool")
	fo, err := os.Create(dirpath + "peer_certificates.pem")
	if err != nil {
		return fmt.Errorf("StoreToPath: %v", err)
	}
	defer fo.Close()
	// make a write buffer
	wr := bufio.NewWriter(fo)

	for _, c := range cm.peerCertsByHash {
		log.Println("Writing cert:", c.Certificate.Subject.CommonName)
		b := &pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate.Raw}
		if err := pem.Encode(wr, b); err != nil {
			return fmt.Errorf("Encoding certificate:%v", err)
		}
	}
	wr.Flush()

	return nil
}
