package client

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/grandcat/flexsmc/authentication"
	"github.com/grandcat/flexsmc/registry"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

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

type Client struct {
	authentication.AuthState
	rpcConn     *grpc.ClientConn
	rpcBalancer grpc.Balancer
	opts        options
}

func NewClient(opts ...Option) Client {
	var conf options
	for _, o := range opts {
		o(&conf)
	}

	return Client{
		opts:      conf,
		AuthState: authentication.NewAuthState(),
	}
}

func (c *Client) prepare() {
	// XXX: load default server certificate for now
	peerCertMgr := c.GetPeerCerts()
	peerCertMgr.LoadFromPath("client/")

	// Custom name resolution with standard RoundRobin balancer
	c.rpcBalancer = grpc.RoundRobin(new(registry.StaticAddrMap))
}

func (c *Client) Dial(peerID string) (*grpc.ClientConn, error) {
	if len(c.opts.keyPairs) == 0 {
		return nil, fmt.Errorf("No TLS key pair loaded.")
	}

	if c.rpcBalancer == nil {
		c.prepare()
	}

	tc := &tls.Config{
		Certificates: c.opts.keyPairs,
		RootCAs:      c.GetPeerCerts().ManagedCertPool,
		ServerName:   peerID, //< necessary as IP SANs do not work in a dynamic environment
		// InsecureSkipVerify: true,
	}
	tc.BuildNameToCertificate()
	ta := credentials.NewTLS(tc)

	// Set up a connection to the server.
	conn, err := grpc.Dial(peerID, grpc.WithTransportCredentials(ta), grpc.WithBalancer(c.rpcBalancer))
	if err != nil {
		return nil, fmt.Errorf("could not connect: %v", err)
	}

	c.rpcConn = conn
	return c.rpcConn, nil
}

func (c *Client) TearDown() {
	c.rpcConn.Close()
	log.Println("client: teardown done")
}
