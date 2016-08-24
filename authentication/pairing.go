package authentication

import (
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	proto "github.com/grandcat/flexsmc/authentication/proto"
	"golang.org/x/net/context"
)

type Pairing interface {
	// MethodNames() string
	// Server-side RPC
	RegisterService(g *grpc.Server)
	Register(ctx context.Context, in *proto.RegisterRequest) (*proto.StatusReply, error)
	// Client-side RPC
	// Register(ctx context.Context, req interface{}) (interface{}, error)
}

type PrWatcher interface {
}

type ApprovalPairing struct {
	certMgr *PeerCertMgr
}

func NewApprovalPairing(p *PeerCertMgr) Pairing {
	return &ApprovalPairing{
		certMgr: p,
	}
}

func (a *ApprovalPairing) RegisterService(g *grpc.Server) {
	proto.RegisterPairingServer(g, a)
	log.Println("Register pairing module for gRPC")
}

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
		if _, err := a.certMgr.AddCert(peerCert, Inactive, time.Now()); err != nil {
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
