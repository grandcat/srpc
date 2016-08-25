package pairing

import (
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/grandcat/srpc"
	"github.com/grandcat/srpc/authentication"
	proto "github.com/grandcat/srpc/pairing/proto"
	"golang.org/x/net/context"
)

type Pairing interface {
	srpc.ServerModule
	// Server-side RPC
	Register(ctx context.Context, in *proto.RegisterRequest) (*proto.StatusReply, error)
	// Client-side RPC
	// Register(ctx context.Context, req interface{}) (interface{}, error)
}

type PrWatcher interface {
}

type ApprovalPairing struct {
	certMgr *authentication.PeerCertMgr
}

func NewApprovalPairing(p *authentication.PeerCertMgr) Pairing {
	return &ApprovalPairing{
		certMgr: p,
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
