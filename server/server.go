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

func (sc *ServerContext) Geti() *authentication.AuthState {
	log.Println("Geti called in ServerContext")
	return &sc.AuthState
}

func Prepare(ctx Serverize) *grpc.Server {
	// Prepare server instance
	// srv := ctx.Geti()
	peerCertMgr := ctx.GetPeerCerts()

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
		peerCertMgr.LoadFromPath("")
	}()

	// Setup HTTPS client
	ta := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{peerCert},
		ClientCAs:    peerCertMgr.ManagedCertPool,
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
