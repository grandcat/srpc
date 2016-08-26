package pairing

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	gtypeAny "github.com/golang/protobuf/ptypes/any"
	gtypeEmpty "github.com/golang/protobuf/ptypes/empty"
	"github.com/grandcat/srpc"
	"github.com/grandcat/srpc/authentication"
	"github.com/grandcat/srpc/client"
	proto "github.com/grandcat/srpc/pairing/proto"
	"golang.org/x/net/context"
)

var (
	StatusRejected = errors.New("pairing rejected by peer")
)

type Pairing interface {
	srpc.ServerModule
	// Server-side RPC
	Register(ctx context.Context, in *proto.RegisterRequest) (*proto.StatusReply, error)
	IncomingRequests() <-chan PeerIdentity
	Status(ctx context.Context, in *gtypeEmpty.Empty) (*proto.StatusReply, error)
	// Client-side RPC
	StartPairing(ctx context.Context, details *gtypeAny.Any) (PeerIdentity, error)
	// TODO: integrate into StartPairing
	AwaitPairingResult(ctx context.Context) <-chan PStatus
}

type PeerIdentity interface {
	Fingerprint() authentication.CertFingerprint
	FingerprintHex() string
	Accept()
	Reject()
}

type ApprovalPairing struct {
	certMgr *authentication.PeerCertMgr
	nch     chan PeerIdentity
	// Client-side
	cc *client.ClientConnPlus
}

func NewServerApproval(p *authentication.PeerCertMgr) Pairing {
	return &ApprovalPairing{
		certMgr: p,
		nch:     make(chan PeerIdentity, 8),
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
			FullMethod: []string{
				"/auth.Pairing/Register",
				"/auth.Pairing/Status",
			},
			Consume: true,
		},
	}
}

// Server API for Pairing service

func certsFromCtx(ctx context.Context) ([]*x509.Certificate, error) {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("pairing: no peer info in ctx")
	}

	var peerCerts []*x509.Certificate
	switch auth := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		log.Println("TLSInfo:", auth.State)
		peerCerts = auth.State.PeerCertificates

	default:
		return nil, fmt.Errorf("pairing: unknown authentication")
	}

	if len(peerCerts) == 0 {
		return nil, fmt.Errorf("pairing: no peer cert given")
	}

	return peerCerts, nil
}

// Register defines the function handler for the server-side RPC service definition.
func (a *ApprovalPairing) Register(ctx context.Context, in *proto.RegisterRequest) (*proto.StatusReply, error) {
	log.Println("RPC `Register` called within ApprovalPairing")
	// Dummy
	// PeerCertMgr temporarily stores the client certificate provided during the TLS session.
	// If Register returns an error, the certificate provided by the client, is not added to the pool at all:
	// E.g. errors.New("Not responsible for this peer")
	// input := in.(*proto.RegisterRequest)
	peerCerts, err := certsFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("pairing: %v", err)
	}

	// Register peer certificate from TLS session as temporary candidate
	if _, err := a.certMgr.AddCert(peerCerts[0], authentication.Inactive, time.Now()); err != nil {
		log.Printf("Error during Pairing Register: %v \n", err)
		return nil, err
	}
	// Notify watcher to decide how to proceed with this new peer
	a.nch <- &peerIdentity{cm: a.certMgr, peerCert: peerCerts[0]}

	return &proto.StatusReply{
		Status: proto.Status_WAITING_APPROVAL,
	}, nil
}

func (a *ApprovalPairing) IncomingRequests() <-chan PeerIdentity {
	return a.nch
}

func (a *ApprovalPairing) Status(ctx context.Context, in *gtypeEmpty.Empty) (*proto.StatusReply, error) {
	peerCerts, err := certsFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("pairing: %v", err)
	}

	r := a.certMgr.Role(peerCerts[0])
	var s proto.Status
	switch r {
	case authentication.Primary, authentication.Backup:
		s = proto.Status_REGISTERED
	case authentication.Inactive:
		s = proto.Status_WAITING_APPROVAL
	default:
		s = proto.Status_REJECTED
	}
	return &proto.StatusReply{
		Status: s,
	}, nil
}

// Client API for Pairing service

func (a *ApprovalPairing) StartPairing(ctx context.Context, details *gtypeAny.Any) (PeerIdentity, error) {
	if a.cc == nil {
		return nil, fmt.Errorf("pairing: no ClientConn")
	}
	c := proto.NewPairingClient(a.cc.CC)

	req := &proto.RegisterRequest{Name: "within pairing mod", Details: details}
	resp, err := c.Register(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("pairing: %v", err)
	}
	fmt.Println("Pairing Resp:", resp)
	if resp.Status == proto.Status_REJECTED {
		return nil, StatusRejected
	}
	// Receive certificate
	var peerCert *x509.Certificate
	select {
	case tlsState := <-a.cc.TLSState:
		peerCert = tlsState.PeerCertificates[0]
		log.Println("Pr: Received TLS Info: ", tlsState.PeerCertificates[0])

	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded || ctx.Err() == context.Canceled {
			return nil, fmt.Errorf("pairing: canceled or timeout: tls session or connection failed")
		}
	}

	// Add remote peer's certificate to pool of interesting ones
	a.certMgr.AddCert(peerCert, authentication.Inactive, time.Now())

	return &peerIdentity{a.certMgr, peerCert}, nil
}

type PStatus proto.Status

func (a *ApprovalPairing) AwaitPairingResult(ctx context.Context) <-chan PStatus {
	notify := make(chan PStatus, 1)
	if a.cc == nil {
		close(notify)
	}
	c := proto.NewPairingClient(a.cc.CC)

	// Poll server for changes in pairing. In case of success or reject, we are done.
	go func(ctx context.Context, c proto.PairingClient, notify chan<- PStatus) {
		t := time.NewTicker(time.Second * 3)
		defer t.Stop()
	polling:
		for {
			select {
			case <-t.C:
				// Do request every timer tick
				resp, err := c.Status(ctx, &gtypeEmpty.Empty{})
				if err != nil {
					close(notify)
					log.Printf("pairing: AwaitPairingResult: %v", err)
					break polling
				}
				if resp.Status != proto.Status_WAITING_APPROVAL {
					notify <- PStatus(resp.Status)
					break polling
				}
				// Continue with ticker on Resp == Status_WAITING_APPROVAL
				log.Println("Peer still not approved our pairing request...")

			case <-ctx.Done():
				if ctx.Err() == context.DeadlineExceeded || ctx.Err() == context.Canceled {
					close(notify)
					log.Println("pairing: canceled or timeout: registration not finished on peer side")
					break polling
				}
			}
		}
	}(ctx, c, notify)

	return notify
}

type peerIdentity struct {
	cm       *authentication.PeerCertMgr
	peerCert *x509.Certificate
}

func (pi *peerIdentity) Fingerprint() authentication.CertFingerprint {
	return authentication.Sha256Fingerprint(pi.peerCert)
}

func (pi *peerIdentity) FingerprintHex() string {
	return authentication.Sha256FingerprintHex(pi.peerCert)
}

func (pi *peerIdentity) Accept() {
	pi.cm.UpdateCert(pi.peerCert, authentication.Primary)
	log.Printf("pairing: accepted peer with fp %s", string(pi.Fingerprint()))
}

func (pi *peerIdentity) Reject() {
	pi.cm.RevokeCert(pi.peerCert)
	log.Printf("pairing: revoked peer with fp %s", string(pi.Fingerprint()))
}
