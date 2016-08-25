package server

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/net/context"

	"github.com/grandcat/srpc/authentication"
	"github.com/grandcat/srpc/pairing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

type Serverize interface {
	authentication.Authorize
	GetServer() *ServerContext
	GetAuthState() *authentication.ClientAuth
}

type options struct {
	keyPairs []tls.Certificate
}

// Option fills the option struct to configure TLS keys etc.
type Option func(*options)

// TLSKeyFile defines the server's TLS certificate used to authenticate
// against a client.
func TLSKeyFile(certFile, keyFile string) Option {
	return func(o *options) {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			panic("could not load TLS cert/key pair")
		}
		o.keyPairs = append(o.keyPairs, c)
	}
}

type ServerContext struct {
	authentication.ClientAuth
	Interceptor *RoutedInterceptor
	Pairing     pairing.Pairing
	// gRPC structs and options
	rpc  *grpc.Server
	opts options
}

func NewServer(opts ...Option) ServerContext {
	var conf options
	for _, o := range opts {
		o(&conf)
	}

	cauth := authentication.NewClientAuth()
	return ServerContext{
		ClientAuth: cauth,
		Pairing:    pairing.NewApprovalPairing(cauth.PeerCerts),
		opts:       conf,
	}
}

func (s *ServerContext) GetAuthState() *authentication.ClientAuth {
	log.Println("GetAuthState called in ServerContext")
	return &s.ClientAuth
}

func (s *ServerContext) GetServer() *ServerContext {
	return s
}

func (s *ServerContext) Prepare() (*grpc.Server, error) {
	peerCertMgr := s.GetPeerCerts()

	// Check server key pair
	if len(s.opts.keyPairs) == 0 {
		return nil, fmt.Errorf("No TLS key pair loaded.")
	}
	// Use global interceptor if no custom one is configured.
	// If using a custom one, be aware that the sever context s might not be
	// available as custom gRPC modules might be registered for this gRPC server
	// instance.
	if s.Interceptor == nil {
		s.Interceptor = GlobalRoutedInterceptor
	}
	// Load client certificate for end2end authentication
	// clientCer.Errorf("No server TLS key pair loaded.") := util.ReadCertFromPEM(*clientCertFile)
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
		if err := peerCertMgr.LoadFromPath(""); err != nil {
			panic(err)
		}
		peerCertMgr.StoreToPath("")
	}()

	// Setup TLS client authentication
	tlsConfig := &tls.Config{
		Certificates: s.opts.keyPairs,
		ClientCAs:    peerCertMgr.ManagedCertPool,
		// NoClientCert
		// RequestClientCert
		// RequireAnyClientCert
		// VerifyClientCertIfGiven
		// RequireAndVerifyClientCert
		// Verification is in authentication.AuthenticateClient. This abstraction is
		// necessary for pairing: adding new certificates on the fly
		ClientAuth: tls.RequireAnyClientCert,
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()
	ta := credentials.NewTLS(tlsConfig)

	s.rpc = grpc.NewServer(grpc.Creds(ta), grpc.UnaryInterceptor(s.Interceptor.Invoke))

	// XXX: Pass server to all modules handling requests by their own
	s.Interceptor.Add(UnaryInterceptInfo{FullMethod: []string{"/auth.Pairing/Register"}, Consume: true})
	s.Interceptor.Add(UnaryInterceptInfo{FullMethod: []string{"*"}, Consume: true, Func: authentication.AuthInterceptor})
	s.ClientAuth.RegisterServer(s.rpc) //< not used
	s.Pairing.RegisterServer(s.rpc)

	return s.rpc, nil
}

// Serve starts listening for incoming connections and serves the requests through
// the RPC backend (gRPC).
// TODO: config listening address
func (s *ServerContext) Serve() error {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
		return err
	}

	err = s.rpc.Serve(lis)
	if err != nil {
		log.Fatalf("rpc backend failed: %v", err)
		return err
	}

	return nil
}

func (s *ServerContext) TearDown() {
	s.rpc.Stop()
}

func invokeUnaryInterceptorChain(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	// s := info.Server.(Serverize).GetServer()
	// return s.intercept.Invoke(ctx, req, info, handler)
	return GlobalRoutedInterceptor.Invoke(ctx, req, info, handler)
}
