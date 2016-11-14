package server

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/grandcat/srpc"
	"github.com/grandcat/srpc/authentication"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

type Serverize interface {
	authentication.Auth
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
	authentication.Auth
	Interceptor *srpc.RoutedInterceptor
	mods        []srpc.ServerModule
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

	// Authentication module is a fixed part. Due to dependencies, load it first.
	clAuth := authentication.NewClientAuth()
	srpc.GlobalRoutedInterceptor.AddMultiple(clAuth.InterceptMethods())
	return Server{
		Auth:        &clAuth,
		Interceptor: srpc.GlobalRoutedInterceptor,
		opts:        conf,
	}
}

func (s *Server) RegisterModules(mods ...srpc.ServerModule) error {
	for _, m := range mods {
		// Register interceptors if any
		if err := s.Interceptor.AddMultiple(m.InterceptMethods()); err != nil {
			return fmt.Errorf("abort loading modules: %v", err)
		}
		s.mods = append(s.mods, m)
		log.Printf("Registered module %#v\n", m)
	}
	return nil
}

func (s *Server) Build() (*grpc.Server, error) {
	peerCertMgr := s.PeerCerts()

	// Check server key pair
	if len(s.opts.keyPairs) == 0 {
		return nil, fmt.Errorf("No TLS key pair loaded.")
	}
	// Use global interceptor if no custom one is configured.
	// If using a custom one, be aware that the sever context s might not be
	// available as custom gRPC modules might be registered for this gRPC server
	// instance.
	// if s.Interceptor == nil {
	// 	s.Interceptor = srpc.GlobalRoutedInterceptor
	// }

	// XXX: dynamically add client cert later
	go func() {
		time.Sleep(5 * time.Second)
		// Import and persist managed certificates to disk
		if err := peerCertMgr.LoadFromPath(""); err != nil {
			fmt.Println(err)
		}
		peerCertMgr.StoreToPath("")
	}()

	// CertPool based on verification strictness as a workaround for gRPC-go.
	// If the server is running in stealth mode, the aim is to reject unknown clients with
	// missing client certificate match at an early stage of the TLS stack.
	// During normal operation, the client verification is done by a separate module to allow
	// features like pairing. In general, this needs less restrictive settings, so
	// 		`ClientAuth <= RequireAnyClientCert`.
	// Normally, the content of `ClientCAs` should not be considered in this case anymore. But
	// it seems to be a bug in grpc-go (28707e14b1d2b2f5da81474dea2790d71e526987).
	//
	// BUG description for gRPC-go:
	// 		If a client tries to establish an unauthenticated conn, and there is 1 entry in
	//		ClientCAs (though ClientAuth: RequireAnyClientCert), it will pretend that the client
	// 		did not send a client certificate. Maybe, there is still some validation in place
	// 		that should be offline by setting `ClientAuth: RequireAnyClientCert`.
	var clientCAs *x509.CertPool
	if s.opts.strictness > tls.RequireAnyClientCert {
		clientCAs = peerCertMgr.ManagedCertPool
	} else {
		clientCAs = x509.NewCertPool()
	}
	// Setup TLS client authentication
	tlsConfig := &tls.Config{
		Certificates: s.opts.keyPairs,
		ClientCAs:    clientCAs,
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
		// SessionTicketsDisabled: true,
	}
	tlsConfig.BuildNameToCertificate()
	ta := credentials.NewTLS(tlsConfig)

	s.rpc = grpc.NewServer(grpc.Creds(ta), grpc.UnaryInterceptor(s.Interceptor.InvokeUnary), grpc.StreamInterceptor(s.Interceptor.InvokeStream))
	// Register server modules for this gRPC server if necessary
	s.Auth.RegisterServer(s.rpc) //< not used
	for _, m := range s.mods {
		m.RegisterServer(s.rpc)
	}

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
	if s.rpc != nil {
		s.rpc.Stop()
	}
}
