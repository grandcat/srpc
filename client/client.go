package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/grandcat/srpc/authentication"
	"github.com/grandcat/srpc/registry"

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
	authentication.ClientAuth
	// gRPC structs
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
		opts:       conf,
		ClientAuth: authentication.NewClientAuth(),
	}
}

func (c *Client) prepare() {
	// XXX: load default server certificate for now
	// peerCertMgr := c.GetPeerCerts()
	// peerCertMgr.LoadFromPath("client/")

	// Custom name resolution with standard RoundRobin balancer
	c.rpcBalancer = grpc.RoundRobin(new(registry.StaticAddrMap))
}

type ClientConnPlus struct {
	CC       *grpc.ClientConn
	TLSState <-chan tls.ConnectionState
}

func (c *Client) DialUnsecure(peerID string) (*ClientConnPlus, error) {
	if len(c.opts.keyPairs) == 0 {
		return nil, fmt.Errorf("Load TLS key pair first.")
	}
	if c.rpcBalancer == nil {
		c.prepare()
	}

	// Export TLS connection state and received server certificate during TLS handshake
	cs := make(chan tls.ConnectionState, 1)
	tlsDialer := func(addr string, timeout time.Duration) (net.Conn, error) {
		tc := &tls.Config{
			Certificates: c.opts.keyPairs,
			RootCAs:      x509.NewCertPool(),
			// Pass CN as IP SANs do not work in a dynamic environment
			ServerName: peerID,
			// Skip verification as we do not know server's certificate yet
			InsecureSkipVerify: true,
		}

		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, tc)
		if err == nil {
			tlsConnState := conn.ConnectionState()
			cs <- tlsConnState
			// log.Println("TLS Info: ", tlsConnState.PeerCertificates[0])
			// c.ClientAuth.PeerCerts.AddCert(tlsConnState.PeerCertificates[0], authentication.Primary, time.Now())
			// c.ClientAuth.PeerCerts.StoreToPath("client/")
		}
		return conn, err
	}
	// Set up a TLS (but insecure) connection to the server.
	// The identity of the server is not clear yet. To initiate a bi-directional certificate
	// exchange, we simply use the mechanism TLS offers with client-side authentication
	// enabled. As gRPC does not offer any possibility to gather the connection state
	// from the current connection (in contrast to the server-side implementation), we
	// bypass its transport security and wrap it in a TLS session through a custom dialer.
	// Note that this approach might be less efficient than gRPC's Http2 TLS integration.
	// Though, if not heavily used, e.g. for pairing, it is fine.
	//
	// The identity of the counterpart must be verified out-of-band due to risk of a MitM attack.
	conn, err := grpc.Dial(peerID, grpc.WithBalancer(c.rpcBalancer), grpc.WithInsecure(), grpc.WithDialer(tlsDialer))
	if err != nil {
		return nil, fmt.Errorf("could not connect: %v", err)
	}

	return &ClientConnPlus{conn, cs}, err
}

func (c *Client) Dial(peerID string) (*grpc.ClientConn, error) {
	if len(c.opts.keyPairs) == 0 {
		return nil, fmt.Errorf("Load TLS key pair first.")
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
