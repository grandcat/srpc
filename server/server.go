package server

import (
	"crypto/tls"
	"flag"
	"log"
	"time"

	"github.com/grandcat/flexsmc/authentication"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	certFile        = flag.String("cert_file", "testdata/cert_server.pem", "Server TLS cert file")
	keyFile         = flag.String("key_file", "testdata/key_server.pem", "Server TLS key file")
	clientCertFile  = flag.String("client_cert_file", "testdata/cert_client1.pem", "Client1 TLS cert file for Auth")
	clientCertFile2 = flag.String("client_cert_file2", "testdata/cert_client2.pem", "Client2 TLS cert file for Auth")
	port            = flag.Int("port", 50051, "The server port")
)

type Serverize interface {
	authentication.Authorize
	Geti() *authentication.AuthState
}

// server is used to implement helloworld.GreeterServer.
type ServerContext struct {
	authentication.AuthState
	cnt int64
}

// // SayHello implements helloworld.GreeterServer
// func (s *ServerContext) SayHello(ctx context.Context, in *proto.HelloRequest) (*proto.HelloReply, error) {
// 	// log.Println("Received request while server context:", s.ctx)
// 	return &proto.HelloReply{Message: "Hello " + in.Name + " with birthday on " + fmt.Sprintf("%#v", in.Birth)}, nil
// }

func NewServer() ServerContext {
	return ServerContext{authentication.NewAuthState(), 0}
}

func (sc ServerContext) Geti() *authentication.AuthState {
	log.Println("Geti called in ServerContext")
	return &sc.AuthState
}

func Prepare(ctx Serverize) *grpc.Server {
	// Prepare server instance
	srv := ctx.Geti()

	// Load server key pair
	peerCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load peer cert/key error:%v", err)
		return nil
	}
	// Load client certificate for end2end authentication
	// clientCert, err := util.ReadCertFromPEM(*clientCertFile)
	// if err != nil {
	// 	panic(err)
	// }
	// clientCert2, err := util.ReadCertFromPEM(*clientCertFile2)
	// if err != nil {
	// 	panic(err)
	// }

	// Test: dynamically add client cert later
	// Result: works, but check for race conditions, e.g. hold server when adding new certs
	go func() {
		time.Sleep(5 * time.Second)
		// log.Println("now adding client cert")
		// log.Println(srv.certMgr.AddCert(clientCert, authentication.Primary))
		// log.Println(srv.certMgr.AddCert(clientCert2, authentication.Primary))
		// Persist managed certificates to disk
		// srv.certMgr.StoreToPath("")
		srv.PeerCerts.LoadFromPath("")
	}()

	// Setup HTTPS client
	ta := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{peerCert},
		ClientCAs:    srv.PeerCerts.ManagedCertPool,
		// NoClientCert
		// RequestClientCert
		// RequireAnyClientCert
		// VerifyClientCertIfGiven
		// RequireAndVerifyClientCert
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	})
	// tlsConfig.BuildNameToCertificate()
	// Interceptor for Client Auth
	ic := grpc.UnaryServerInterceptor(authentication.Authi)

	// lis, err := net.Listen("tcp", ":50051")
	// if err != nil {
	// 	log.Fatalf("failed to listen: %v", err)
	// }
	s := grpc.NewServer(grpc.Creds(ta), grpc.UnaryInterceptor(ic))
	// Register proto service
	// // proto.RegisterGreeterServer(s, srv)
	// s.Serve(lis)

	return s
}

// func authenticateClient(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
// 	srvCtx := info.Server.(*ServerContext)
// 	log.Println("[", srvCtx.cnt, "] Intercepted call. Func:", info.FullMethod)
// 	srvCtx.cnt++

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
// 		identity, err := srvCtx.PeerCerts.VerifyPeerIdentity(peerCert)
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
