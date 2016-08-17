package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/grandcat/flexsmc/client"
	proto "github.com/grandcat/flexsmc/helloworld"
	"github.com/grandcat/flexsmc/server"
	"golang.org/x/net/context"
)

var (
	isClient       = flag.Bool("client", false, "Set to true to run the client part")
	certFile       = flag.String("cert_file", "testdata/cert_server.pem", "Server TLS cert file")
	keyFile        = flag.String("key_file", "testdata/key_server.pem", "Server TLS key file")
	clientCertFile = flag.String("client_cert_file", "testdata/cert_client1.pem", "Client1 TLS cert file for Auth")
	clientKeyFile  = flag.String("client_key_file", "testdata/key_client1.pem", "Client TLS key file")
)

type Logic struct {
	server.ServerContext
	// Good place for persisting own data
}

// SayHello implements helloworld.GreeterServer
func (s *Logic) SayHello(ctx context.Context, in *proto.HelloRequest) (*proto.HelloReply, error) {
	// log.Println("Received request while server context:", s.ctx)
	return &proto.HelloReply{Message: "Hello " + in.Name + " with birthday on " + fmt.Sprintf("%#v", in.Birth)}, nil
}

func main() {
	flag.Parse()

	if *isClient {
		testClient()

	} else {
		// Configure server options
		tlsKeyPrim := server.TLSKeyFile(*certFile, *keyFile)

		allServer := &Logic{server.NewServer(tlsKeyPrim)}
		// myServer := LogicEntity(baseServer)
		// innerServer := server.Serverize(myServer)
		// innerServer := server.Serverize(allServer)
		// g, _ := server.Prepare(server.Serverize(allServer))

		g, err := allServer.Prepare()
		if err != nil {
			panic(err)
		}
		proto.RegisterGreeterServer(g, allServer)
		allServer.Serve()
		log.Println("Serve() stopped")

	}

}

func testClient() {
	const peerID = "gw4242.flexsmc.local"
	log.Println("Running client...")

	tlsKeyPrim := client.TLSKeyFile(*clientCertFile, *clientKeyFile)
	cl := client.NewClient(tlsKeyPrim)

	conn, err := cl.Dial(peerID)
	if err != nil {
		panic(err)
	}
	c := proto.NewGreeterClient(conn)

	// RPC calls
	for i := 0; i < 3; i++ {
		resp, err := c.SayHello(context.Background(), &proto.HelloRequest{Name: "Mrs.RPC", Birth: &proto.CalenderDay{Year: 1991, Month: 42, Day: 42}})
		if err != nil {
			log.Fatalf("could not greet: %v", err)
		}
		log.Printf("[%d] Greeting: %s", i, resp.Message)

	}
}
