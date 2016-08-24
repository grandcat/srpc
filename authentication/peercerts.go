package authentication

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	util "github.com/grandcat/flexsmc/common"
)

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
	Created     time.Time         `json:"created"`
}

// NewCertManager creates a new instance to manage our own and peers' certificates
func NewPeerCertMgr() *PeerCertMgr {
	return &PeerCertMgr{
		peerCertsByCN:   make(map[string][]*PeerCert),
		peerCertsByHash: make(map[CertFingerprint]*PeerCert),
		ManagedCertPool: x509.NewCertPool(),
	}
}

type PeerCertMgr struct {
	// Map each peer's qualified name (=CN) to its certificates
	peerCertsByCN   map[string][]*PeerCert
	peerCertsByHash map[CertFingerprint]*PeerCert
	mu              sync.RWMutex

	ManagedCertPool *x509.CertPool
}

func (cm *PeerCertMgr) ActivePeerCertificates(cn string) int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	p, ok := cm.peerCertsByCN[cn]
	if ok {
		activeCerts := 0
		for _, c := range p {
			if c.Role >= Primary {
				activeCerts++
			}
		}
		return activeCerts
	}

	return 0
}

// AddCert adds a new certificate and associates it with the peer's CN.
//
// If a peer with the same CN exists, it is associated with this peer. The application
// should check before whether a peer exists if this variant is not desired.
func (cm *PeerCertMgr) AddCert(cert *x509.Certificate, role CertRole, created time.Time) (CertFingerprint, error) {
	// Use cert's CommonName and fingerprint for identification
	cn := cert.Subject.CommonName
	fp := Sha256Fingerprint(cert)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Check if peer CN is not already in use. We enforce unique CNs for
	// individual peers
	if _, exists := cm.peerCertsByHash[fp]; exists {
		return "", fmt.Errorf("CertManager: ignore duplicate cert")
	}
	if len(cm.peerCertsByCN[cn]) > 8 {
		return "", fmt.Errorf("CertManager: too many certificates for this peer")
	}

	newCert := &PeerCert{
		Certificate: cert,
		Role:        role,
		Created:     created,
	}
	// Map cert to array of certs associated with the same CN
	cm.peerCertsByCN[cn] = append(cm.peerCertsByCN[cn], newCert)
	// Associate cert with its unique Sha256 fingerprint
	cm.peerCertsByHash[fp] = newCert
	log.Println("Cert fingerprint:", fp)

	// Map cert to the reference cert pool.
	// This is valid as every request needs to pass the interceptor verifying
	// the validity of the certificate.
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

		// Propagate changes
		cm.buildCertPool()
	}
}

func (cm *PeerCertMgr) VerifyPeerIdentity(remote *x509.Certificate) (*PeerCert, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Primary check:
	// Do same verification steps as in `processCertsFromClient()` (part of `handshake_server.go`)
	// if ClientAuth was RequireAndVerifyClientCert.
	// Like this, we are more flexible while TLS still verifies if the client is in possession of the
	// private key of the certificate (signed digest of all preceding handshake-layer messages).
	opts := x509.VerifyOptions{
		Roots:         cm.ManagedCertPool,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	chains, err := remote.Verify(opts)
	if err != nil {
		return nil, errors.New("peercerts: failed to verify client's certificate: " + err.Error())
	}
	log.Println("Verfied cert chains:", chains)

	// Secondary check:
	// Check role of deposited certificate for the requesting peer
	fp := Sha256Fingerprint(remote)
	if c, ok := cm.peerCertsByHash[fp]; ok {
		// Check for same PeerID
		if c.Certificate.Subject.CommonName != remote.Subject.CommonName {
			return nil, fmt.Errorf("CN not matching")
		}
		// Check whether it is an active certificate
		if c.Role <= Inactive {
			return nil, fmt.Errorf("certificate not active")
		}
		// Further checks should be already done during the TLS handshake, e.g.
		// signing and verifying all messages previously sent.
		return c, nil
	}

	return nil, fmt.Errorf("no matching certificate")
}

func (cm *PeerCertMgr) buildCertPool() {
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

// LoadFromPath imports certificates from `peer_certificates.pem` into the local
// certificate pool. If a certificate in the pool is the same as one of the
// imported ones, it is skipped.
// Note: only certificates described by `peer_certificates.meta.json`, are
//		 candidates for import.
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

	// Load all certificates from PEM file. With available meta information,
	// we decide to keep it
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
			cm.AddCert(c, meta.Role, meta.Created)
		} else {
			fmt.Errorf("skipping certificate %s as not part of meta file.\n",
				Sha256Fingerprint(c))
		}
	}

	return nil
}

// StoreToPath exports all managed certificates accompanied by a JSON meta file for
// additional properties, such as its role or issue time.
func (cm *PeerCertMgr) StoreToPath(dirpath string) error {
	// Extract base path
	dirpath = filepath.Dir(dirpath) + string(os.PathSeparator)

	// Write metadata for all managed peer certificates
	cm.mu.RLock()
	js, err := json.Marshal(cm.peerCertsByHash)
	cm.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("StoreToPath: %v", err)
	}
	ioutil.WriteFile(dirpath+"peer_certificates.meta.json", js, 0644)

	// Write all certificates to a common PEM encoded file
	log.Printf("Exporting %d certificates from peer cert pool", len(cm.peerCertsByHash))
	fo, err := os.Create(dirpath + "peer_certificates.pem")
	if err != nil {
		return fmt.Errorf("StoreToPath: %v", err)
	}
	defer fo.Close()
	// make a write buffer
	wr := bufio.NewWriter(fo)

	cm.mu.RLock()
	defer cm.mu.RUnlock()
	for _, c := range cm.peerCertsByHash {
		log.Println("Writing cert:", c.Certificate.Subject.CommonName)
		b := &pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate.Raw}
		if err := pem.Encode(wr, b); err != nil {
			return fmt.Errorf("encoding certificate:%v", err)
		}
	}
	wr.Flush()

	return nil
}
