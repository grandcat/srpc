package pairing

import (
	"crypto/x509"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/grandcat/srpc"
	"github.com/grandcat/srpc/authentication"
	"github.com/grandcat/srpc/client"
	proto "github.com/grandcat/srpc/pairing/proto"
	"golang.org/x/net/context"
)

type Pairing interface {
	srpc.ServerModule
	// Server-side RPC
	Register(ctx context.Context, in *proto.RegisterRequest) (*proto.StatusReply, error)
	// Client-side RPC
	StartPairing(ctx context.Context, peerID string) (PeerIdentity, error)
}

type PeerIdentity interface {
	Fingerprint() authentication.CertFingerprint
	Accept()
	Reject()
}

type ApprovalPairing struct {
	certMgr *authentication.PeerCertMgr
	// Client-side
	cc *client.ClientConnPlus
}

func NewServerApproval(p *authentication.PeerCertMgr) Pairing {
	return &ApprovalPairing{
		certMgr: p,
	}
}

func NewClientApproval(p *authentication.PeerCertMgr, cc *client.ClientConnPlus) Pairing {
	return &ApprovalPairing{
		certMgr: p,
		cc:      cc,
	}
}

func (a *ApprovalPairing) RegisterServer(g *grpc.Server) {
	proto.RegisterPairingServer(g, a)
	log.Println("Register pairing service handler for gRPC")
}

func (a *ApprovalPairing) InterceptMethods() []srpc.UnaryInterceptInfo {
	return []srpc.UnaryInterceptInfo{
		srpc.UnaryInterceptInfo{
			FullMethod: []string{"/auth.Pairing/Register"},
			Consume:    true,
		},
	}
}

// Server API for Pairing service

// Register defines the function handler for the server-side RPC service definition.
func (a *ApprovalPairing) Register(ctx context.Context, in *proto.RegisterRequest) (*proto.StatusReply, error) {
	log.Println("RPC `Register` called within ApprovalPairing")
	// Dummy
	// PeerCertMgr temporarily stores the client certificate provided during the TLS session.
	// If Register returns an error, the certificate provided by the client, is not added to the pool at all:
	// E.g. errors.New("Not responsible for this peer")
	// input := in.(*proto.RegisterRequest)
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("Failed to get peer info from ctx")
	}

	switch auth := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		log.Println("TLSInfo:", auth.State)
		peerCert := auth.State.PeerCertificates[0]
		// Register peer certificate from TLS session as temporary candidate
		if _, err := a.certMgr.AddCert(peerCert, authentication.Inactive, time.Now()); err != nil {
			log.Printf("Error during Pairing Register: %v \n", err)

			return nil, err
			// return &proto.StatusReply{
			// 	Status: proto.Status_REJECTED,
			// }, nil
		}

	default:
		return nil, fmt.Errorf("Unknown authentication")
	}

	return &proto.StatusReply{
		Status: proto.Status_WAITING_APPROVAL,
	}, nil
}

// Client API for Pairing service

func (a *ApprovalPairing) StartPairing(ctx context.Context, peerID string) (PeerIdentity, error) {
	if a.cc == nil {
		// TODO: error handling via PeerIdentity
		return nil, fmt.Errorf("pairing: no ClientConn")
	}
	c := proto.NewPairingClient(a.cc.CC)

	req := &proto.RegisterRequest{Name: "within pairing mod"}
	if resp, err := c.Register(ctx, req); err == nil {
		fmt.Println("Pairing Resp:", resp)
	}
	// Receive certificate
	var peerCert *x509.Certificate
	select {
	case tlsState := <-a.cc.TLSState:
		peerCert = tlsState.PeerCertificates[0]
		log.Println("Pr: Received TLS Info: ", tlsState.PeerCertificates[0])

	case <-time.After(3 * time.Second):
		return nil, fmt.Errorf("pairing: timeout: tls session or connection failed")
	}

	// Add remote peer's certificate to pool of interesting ones
	a.certMgr.AddCert(peerCert, authentication.Inactive, time.Now())

	return &peerIdentity{a.certMgr, peerCert}, nil
}

type peerIdentity struct {
	cm       *authentication.PeerCertMgr
	peerCert *x509.Certificate
}

func (pi *peerIdentity) Fingerprint() authentication.CertFingerprint {
	return authentication.Sha256Fingerprint(pi.peerCert)
}

func (pi *peerIdentity) Accept() {
	pi.cm.UpdateCert(pi.peerCert, authentication.Primary)
	log.Printf("pairing: accepted peer with fp %s", string(pi.Fingerprint()))
}

func (pi *peerIdentity) Reject() {
	pi.cm.RevokeCert(pi.peerCert)
	log.Printf("pairing: revoked peer with fp %s", string(pi.Fingerprint()))
}
