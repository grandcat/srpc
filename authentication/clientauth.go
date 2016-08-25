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
	RegisterServer(*grpc.Server)
	GetPeerCerts() *PeerCertMgr
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

func (ca *ClientAuth) GetPeerCerts() *PeerCertMgr {
	return ca.PeerCerts
}

func (ca *ClientAuth) RegisterServer(g *grpc.Server) {
	// Nothing to do
}

// Auth contains the information of the succeeded (or failed) authentication for an RPC.
type Auth struct {
	PeerID   string
	Verified bool
}

type authKey struct{}

// NewAuthContext creates a new context with authentication information attached.
func NewAuthContext(ctx context.Context, a *Auth) context.Context {
	return context.WithValue(ctx, authKey{}, a)
}

// FromAuthContext returns the authentication details from ctx if exists.
func FromAuthContext(ctx context.Context) (a *Auth, ok bool) {
	a, ok = ctx.Value(authKey{}).(*Auth)
	return
}

func AuthInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	log.Println("Intercepted call. Func:", info.FullMethod)

	// Bypass authentication through certificate verification
	if info.FullMethod == "/auth.Pairing/Register" {
		log.Println("Should not go inside here!!!")
		// For pairing, checks are less restrictive as it should be an unknown certificate.
		// Still, we need to take care of the result by the higher-level handler before
		// putting the certificate to the pool.
		m, err := handler(ctx, req)
		// pairing := srvCtx.Pairer()
		// m, err := pairing.Register(ctx, req)

		// if err == nil {
		// 	if _, err := peerCertMgr.AddCert(peerCert, Inactive, time.Now()); err != nil {
		// 		return nil, fmt.Errorf("clientauth: %v", err.Error())
		// 	}
		// }
		return m, err
	}

	pr, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("Failed to get peer info from ctx")
	}

	switch auth := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		log.Println("TLSInfo:", auth.State)
		peerCert := auth.State.PeerCertificates[0]

		srvCtx := info.Server.(Authorize)
		peerCertMgr := srvCtx.GetPeerCerts()
		// Check for peer's identity being available and valid, otherwise abort
		identity, err := peerCertMgr.VerifyPeerIdentity(peerCert)
		if err == nil {
			ctx = NewAuthContext(ctx, &Auth{PeerID: peerCert.Subject.CommonName, Verified: true})
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
