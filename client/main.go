package client

// import (
// 	"crypto/tls"
// 	"flag"
// 	"log"
// 	"os"

// 	"github.com/grandcat/flexsmc/authentication"
// 	"github.com/grandcat/flexsmc/registry"
// 	util "github.com/grandcat/grpctls/common"
// 	proto "github.com/grandcat/grpctls/helloworld"
// 	"golang.org/x/net/context"
// 	"google.golang.org/grpc"
// 	"google.golang.org/grpc/credentials"
// )

// const (
// 	peerid      = "gw4242.flexsmc.local"
// 	defaultName = "world"
// )

// var (
// 	certFile       = flag.String("cert_file", "testdata/cert_client1.pem", "Client TLS cert file")
// 	keyFile        = flag.String("key_file", "testdata/key_client1.pem", "Client TLS key file")
// 	serverCertFile = flag.String("client_cert_file", "testdata/cert_server.pem", "Server TLS cert file as CA")
// )

// func main() {
// 	// Setup TLS
// 	// load peer cert/key, cacert
// 	peerCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
// 	if err != nil {
// 		log.Panicf("load peer cert/key error:%v", err)
// 	}
// 	// Load server cert (peer in this case)
// 	peerCerts := authentication.NewPeerCertMgr()
// 	caCert, err := util.ReadCertFromPEM(*serverCertFile)
// 	if err != nil {
// 		panic(err)
// 	}
// 	peerCerts.AddCert(caCert, authentication.Primary)
// 	log.Println("Server cert CN:", caCert.Subject.CommonName)

// 	ta := credentials.NewTLS(&tls.Config{
// 		Certificates: []tls.Certificate{peerCert},
// 		RootCAs:      peerCerts.ManagedCertPool,
// 		ServerName:   peerid, //< if domain name of server certificate is wrong
// 		// InsecureSkipVerify: true,
// 	})

// 	// Custom name resolution using standard RoundRobin balancer
// 	ba := grpc.RoundRobin(new(registry.StaticAddrMap))

// 	// Set up a connection to the server.
// 	conn, err := grpc.Dial(peerid, grpc.WithTransportCredentials(ta), grpc.WithBalancer(ba))
// 	if err != nil {
// 		log.Fatalf("did not connect: %v", err)
// 	}
// 	defer conn.Close()

// 	// ...or somehow wrap this function in a nice way
// 	c := proto.NewGreeterClient(conn)

// 	// Contact the server and print out its response.
// 	name := defaultName
// 	if len(os.Args) > 1 {
// 		name = os.Args[1]
// 	}

// 	for i := 0; i < 3; i++ {
// 		resp, err := c.SayHello(context.Background(), &proto.HelloRequest{Name: name, Birth: &proto.CalenderDay{Year: 1991, Month: 42, Day: 42}})
// 		if err != nil {
// 			log.Fatalf("could not greet: %v", err)
// 		}
// 		log.Printf("[%d] Greeting: %s", i, resp.Message)

// 	}

// }
