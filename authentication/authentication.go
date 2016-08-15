package authentication

import (
	"log"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
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

func Authi(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	log.Println("Intercepted call. Func:", info.FullMethod)
	srvCtx := info.Server.(Authorize)
	pcm := srvCtx.GetPeerCerts()
	// log.Println("Server:", srvCtx)
	log.Println("Getii in Authi:", pcm)

	return handler(ctx, req)
}

// func authenticateClient(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
// 	log.Println("Intercepted call. Func:", info.FullMethod)
// 	srvCtx := info.Server.(*AuthState)

// 	// Check certificate sent by client
// 	pr, ok := peer.FromContext(ctx)
// 	if !ok {
// 		return nil, fmt.Errorf("Failed to get peer from ctx")
// 	}
// 	switch info := pr.AuthInfo.(type) {
// 	case credentials.TLSInfo:
// 		peerCert := info.State.PeerCertificates[0]
// 		// log.Println("[", info.State.ServerName, "] Peer Cert:", peerCert.Signature)

// 		cn := peerCert.Subject.CommonName
// 		log.Println("Subject:", cn)
// 		log.Println("Raw Subject:", string(peerCert.RawSubject)) // same as RawIssuer for self-signed certs
// 		// log.Println("Raw Issuer:", string(peerCert.RawIssuer))

// 		// Check for correct peer's identity being valid, otherwise abort
// 		identity, err := srvCtx.certMgr.VerifyPeerIdentity(peerCert)
// 		if err == nil {
// 			log.Printf("Peer identity ok: %v \n", identity)
// 		} else {
// 			return nil, err
// 		}

// 	default:
// 		return nil, fmt.Errorf("Unknown AuthInfo type")
// 	}

// 	log.Println("Peer src addr:", pr.Addr)

// 	// Is a valid peer -> handle RPC request as usual
// 	return handler(ctx, req)
// }
