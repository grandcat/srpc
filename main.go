package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	util "github.com/grandcat/flexsmc/common"
	proto "github.com/grandcat/flexsmc/helloworld"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

var (
	certFile       = flag.String("cert_file", "testdata/cert_server.pem", "Server TLS cert file")
	keyFile        = flag.String("key_file", "testdata/key_server.pem", "Server TLS key file")
	clientCertFile = flag.String("client_cert_file", "testdata/cert_client1.pem", "Client TLS cert file for Auth")
	port           = flag.Int("port", 50051, "The server port")

	cert = make(map[string]*x509.Certificate)
)

// server is used to implement helloworld.GreeterServer.
type server struct {
	ctx string
}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context, in *proto.HelloRequest) (*proto.HelloReply, error) {
	log.Println("Received request while server context:", s.ctx)
	return &proto.HelloReply{Message: "Hello " + in.Name + " with birthday on " + fmt.Sprintf("%#v", in.Birth)}, nil
}

func main() {

	// Load server key pair
	peerCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load peer cert/key error:%v", err)
		return
	}
	// Load client certificate for end2end authentication
	clientCert, err := util.ReadCertFromPEM(*clientCertFile)
	if err != nil {
		panic(err)
	}
	caCertPool := x509.NewCertPool()

	// Test: dynamically add client cert later
	// Result: works, but check for race conditions, e.g. hold server when adding new certs
	go func() {
		time.Sleep(5 * time.Second)
		log.Println("now adding client cert")
		caCertPool.AddCert(clientCert)
	}()
	cert["raspi.local"] = clientCert
	log.Println("All certs:", cert)

	// Setup HTTPS client
	ta := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{peerCert},
		ClientCAs:    caCertPool,
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
	ic := grpc.UnaryServerInterceptor(authenticateClient)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(ta), grpc.UnaryInterceptor(ic))
	proto.RegisterGreeterServer(s, &server{ctx: "passed const string"})
	s.Serve(lis)
}

func authenticateClient(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	log.Println("Intercepted call. Func:", info.FullMethod)

	// Check certificate sent by client
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("Failed to get peer from ctx")
	}
	switch info := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		peerCert := info.State.PeerCertificates[0]
		log.Println("[", info.State.ServerName, "] Peer Cert:", peerCert.Signature)

		cn := peerCert.Subject.CommonName
		log.Println("Subject:", cn)
		// Fetch subject's key and compare to the one used in the current TLS session
		subjCert, ok := cert[cn]
		if ok {
			eqCerts := peerCert.Equal(subjCert)
			log.Println("Matching certs?", eqCerts)
		} else {
			return nil, fmt.Errorf("No registered cert for this peer")
		}

	default:
		return nil, fmt.Errorf("Unknown AuthInfo type")
	}

	log.Println("Peer src addr:", pr.Addr)

	// Is a valid peer -> handle RPC request as usual
	return handler(ctx, req)
}
