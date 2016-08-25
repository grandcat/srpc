package authentication

import (
	"fmt"
	"log"

	"github.com/grandcat/srpc"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type Auth interface {
	srpc.ServerModule
	GetPeerCerts() *PeerCertMgr
}

type authStateKey struct{}

// NewAuthContext creates a new context with authentication information attached.
func NewAuthContext(ctx context.Context, a *AuthState) context.Context {
	return context.WithValue(ctx, authStateKey{}, a)
}

// FromAuthContext returns the authentication details from ctx if exists.
func FromAuthContext(ctx context.Context) (a *AuthState, ok bool) {
	a, ok = ctx.Value(authStateKey{}).(*AuthState)
	return
}

type ClientAuth struct {
	PeerCerts *PeerCertMgr
}

func NewClientAuth() ClientAuth {
	m := NewPeerCertMgr()
	return ClientAuth{
		PeerCerts: m,
	}
}

func (ca *ClientAuth) RegisterServer(g *grpc.Server) {
	// Do not register own services. We just intercept all unary gRPC calls and
	// validate them if not handled otherwise in the global interceptor. E.g., for
	// pairing, our authentication handler is not invoked.
}

func (ca *ClientAuth) InterceptMethods() []srpc.UnaryInterceptInfo {
	return []srpc.UnaryInterceptInfo{
		srpc.UnaryInterceptInfo{
			FullMethod: []string{"*"},
			Consume:    true,
			Func:       authInterceptor,
		},
	}
}

func (ca *ClientAuth) GetPeerCerts() *PeerCertMgr {
	return ca.PeerCerts
}

// Auth contains the information of the succeeded (or failed) authentication for an RPC.
type AuthState struct {
	PeerID   string
	Verified bool
}

func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	log.Println("Auth: Intercepted call. Func:", info.FullMethod)

	// Bypass authentication through certificate verification
	if info.FullMethod == "/auth.Pairing/Register" {
		panic("Should not go inside here!!!")
	}

	pr, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("Failed to get peer info from ctx")
	}

	switch auth := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		log.Println("TLSInfo:", auth.State)
		peerCert := auth.State.PeerCertificates[0]

		srvCtx := info.Server.(Auth)
		peerCertMgr := srvCtx.GetPeerCerts()
		// Check for peer's identity being available and valid, otherwise abort
		identity, err := peerCertMgr.VerifyPeerIdentity(peerCert)
		if err == nil {
			ctx = NewAuthContext(ctx, &AuthState{PeerID: peerCert.Subject.CommonName, Verified: true})
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
