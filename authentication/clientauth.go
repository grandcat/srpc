package authentication

import (
	"fmt"
	"log"
	"net"

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

// AuthState contains the information about the succeeded (or failed) client authentication.
type AuthState struct {
	ID       PeerID
	Addr     net.Addr
	Verified bool
}

// NewAuthContext creates a new context appending authentication information.
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
			UnaryFunc:  authenticateUnary,
			StreamFunc: authenticateStream,
		},
	}
}

func (ca *ClientAuth) GetPeerCerts() *PeerCertMgr {
	return ca.PeerCerts
}

func authenticate(ctx context.Context, server interface{}) (context.Context, error) {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("Failed to get peer info from ctx")
	}

	switch auth := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		log.Println(">>TLSInfo:", auth.State)
		peerCert := auth.State.PeerCertificates[0]

		if srvCtx, ok := server.(Auth); ok {
			peerCertMgr := srvCtx.GetPeerCerts()
			// Check for peer's identity being available and valid, otherwise abort
			identity, err := peerCertMgr.VerifyPeerIdentity(peerCert)
			if err == nil {
				ctx = NewAuthContext(ctx, &AuthState{ID: PeerID(peerCert.Subject.CommonName), Addr: pr.Addr, Verified: true})
				log.Printf("Peer identity ok: %v \n", identity)
			} else {
				return nil, err
			}

		} else {
			// No server instance. Probably, it is another server module registered a separate gRPC context.
			// In this case, an routed, consuming interceptor needs to be defined so this function is not reached.
			return nil, fmt.Errorf("internal server error: wrong gRPC server context")
		}

	default:
		return nil, fmt.Errorf("unknown authentication")
	}

	return ctx, nil
}

func authenticateUnary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	ctx, err = authenticate(ctx, info.Server)
	if err != nil {
		return nil, err
	}
	// Authentication passed: invoke original unary handler with authentication
	// result appended to context.
	return handler(ctx, req)
}

func authenticateStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := authenticate(ss.Context(), srv)
	if err != nil {
		return err
	}
	// Authentication passed: invoke original stream handler with authentication
	// result appended to context.
	css := &ContextualServerStream{ServerStream: ss, Ctx: ctx}
	return handler(srv, css)
}
