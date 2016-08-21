package authentication

import (
	"fmt"
	"log"
	"time"

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

	pr, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("Failed to get peer info from ctx")
	}
	srvCtx := info.Server.(Authorize)
	peerCertMgr := srvCtx.GetPeerCerts()

	switch auth := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		log.Println("TLSInfo:", auth.State)
		peerCert := auth.State.PeerCertificates[0]

		// TODO: replace hardcoded mechanism
		if info.FullMethod == "/pairing.Pairing/Register" {
			// For pairing, checks are less restrictive as it should be an unknown certificate.
			// Still, we need to take care of the result by the higher-level handler before
			// putting the certificate to the pool.
			m, err := handler(ctx, req)
			if err == nil {
				if _, err := peerCertMgr.AddCert(peerCert, Inactive, time.Now()); err != nil {
					return nil, fmt.Errorf("clientauth: %v", err.Error())
				}

			}
			return m, err

		}
		// Check for peer's identity being available and valid, otherwise abort
		identity, err := peerCertMgr.VerifyPeerIdentity(peerCert)
		if err == nil {
			log.Printf("Peer identity ok: %v \n", identity)
		} else {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("Unknown authentication")
	}

	// If we reached that far, it should be a valid peer.
	return handler(ctx, req)
}
