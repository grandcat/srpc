package server

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/grandcat/srpc"
	"github.com/grandcat/srpc/authentication"
	"github.com/grandcat/srpc/pairing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

type Serverize interface {
	authentication.Auth
	GetServer() *Server
}

type options struct {
	keyPairs   []tls.Certificate
	strictness tls.ClientAuthType
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

// StealthMode sets the gRPC in a mode to authenticate only known devices.
// This means that modules like pairing will fail as a new client cannot
// succeed in the TLS handshake. No interceptor will be triggered if
// TLS fails.
func StealthMode() Option {
	return func(o *options) {
		o.strictness = tls.RequireAndVerifyClientCert
	}
}

type Server struct {
	// authentication.ClientAuth
	authentication.Auth
	Interceptor *srpc.RoutedInterceptor
	Pairing     pairing.Pairing
	// gRPC structs and options
	rpc  *grpc.Server
	opts options
}

func NewServer(opts ...Option) Server {
	var conf options
	// Default options
	conf.strictness = tls.RequireAnyClientCert
	// Apply external config
	for _, o := range opts {
		o(&conf)
	}

	clAuth := authentication.NewClientAuth()
	return Server{
		Auth:    &clAuth,
		Pairing: pairing.NewServerApproval(clAuth.GetPeerCerts()),
		opts:    conf,
	}
}

func (s *Server) GetServer() *Server {
	return s
}

func (s *Server) Prepare() (*grpc.Server, error) {
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
		s.Interceptor = srpc.GlobalRoutedInterceptor
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
		// Default is tls.RequireAnyClientCert.
		// Verification is in authentication.AuthenticateClient. This abstraction is
		// necessary for pairing: adding new certificates on the fly
		ClientAuth: s.opts.strictness,
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()
	ta := credentials.NewTLS(tlsConfig)

	// XXX: Pass server to all modules handling requests by their own
	s.Interceptor.AddMultiple(s.Pairing.InterceptMethods())
	s.Interceptor.AddMultiple(s.Auth.InterceptMethods())

	s.rpc = grpc.NewServer(grpc.Creds(ta), grpc.UnaryInterceptor(s.Interceptor.Invoke))
	s.Auth.RegisterServer(s.rpc) //< not used
	s.Pairing.RegisterServer(s.rpc)

	return s.rpc, nil
}

// Serve starts listening for incoming connections and serves the requests through
// the RPC backend (gRPC).
// TODO: config listening address
func (s *Server) Serve() error {
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

func (s *Server) TearDown() {
	s.rpc.Stop()
}
