package authentication

import (
	"fmt"
	"log"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type Authorize interface {
	GetPeerCerts() *PeerCertMgr
}

type AuthState struct {
	PeerCerts *PeerCertMgr
}

func NewAuthState() AuthState {
	return AuthState{
		PeerCerts: NewPeerCertMgr(),
	}
}

func (as *AuthState) GetPeerCerts() *PeerCertMgr {
	return as.PeerCerts
}

func AuthenticateClient(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	log.Println("Intercepted call. Func:", info.FullMethod)

	// Check certificate sent by client
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("Failed to get peer info from ctx")
	}
	srvCtx := info.Server.(Authorize)
	peerCertMgr := srvCtx.GetPeerCerts()

	switch info := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		peerCert := info.State.PeerCertificates[0]
		// Check for peer's identity being available and valid, otherwise abort
		identity, err := peerCertMgr.VerifyPeerIdentity(peerCert)
		if err == nil {
			log.Printf("Peer identity ok: %v \n", identity)
		} else {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("Unknown AuthInfo")
	}

	// If we reached that far, it should be a valid peer
	return handler(ctx, req)
}
