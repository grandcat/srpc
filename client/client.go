package client

import (
	"crypto/tls"
	"fmt"

	"github.com/grandcat/flexsmc/authentication"
	"github.com/grandcat/flexsmc/registry"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type options struct {
	keyPairs []tls.Certificate
}

// ClientOption fills the option struct to configure TLS keys etc.
type ClientOption func(*options)

// TLSKeyFile defines the server's TLS certificate used to authenticate
// against a client.
func TLSKeyFile(certFile, keyFile string) ClientOption {
	return func(o *options) {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			panic("could not load TLS cert/key pair")
		}
		o.keyPairs = append(o.keyPairs, c)
	}
}

type Client struct {
	authentication.AuthState
	rpcConn *grpc.ClientConn
	opts    options
}

func NewClient(opts ...ClientOption) Client {
	var conf options
	for _, o := range opts {
		o(&conf)
	}

	return Client{
		opts:      conf,
		AuthState: authentication.NewAuthState(),
	}
}

func (c *Client) Dial(peerID string) (*grpc.ClientConn, error) {
	peerCertMgr := c.GetPeerCerts()

	if len(c.opts.keyPairs) == 0 {
		return nil, fmt.Errorf("No TLS key pair loaded.")
	}

	// XXX: load default server certificate for now
	peerCertMgr.LoadFromPath("client/")

	tc := &tls.Config{
		Certificates: c.opts.keyPairs,
		RootCAs:      peerCertMgr.ManagedCertPool,
		ServerName:   peerID, //< necessary as IP SANs do not work in a dynamic environment
		// InsecureSkipVerify: true,
	}
	tc.BuildNameToCertificate()
	ta := credentials.NewTLS(tc)

	// Custom name resolution using standard RoundRobin balancer
	ba := grpc.RoundRobin(new(registry.StaticAddrMap))
	// Set up a connection to the server.
	conn, err := grpc.Dial(peerID, grpc.WithTransportCredentials(ta), grpc.WithBalancer(ba))
	if err != nil {
		return nil, fmt.Errorf("could not connect: %v", err)
	}

	c.rpcConn = conn
	return c.rpcConn, nil
}
