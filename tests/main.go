package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/grandcat/srpc/authentication"
	"github.com/grandcat/srpc/client"
	proto "github.com/grandcat/srpc/helloworld"
	"github.com/grandcat/srpc/pairing"
	"github.com/grandcat/srpc/server"
	"golang.org/x/net/context"
)

var (
	isClient       = flag.Bool("client", false, "Set to true to run the client part")
	certFile       = flag.String("cert_file", "testdata/cert_server.pem", "Server TLS cert file")
	keyFile        = flag.String("key_file", "testdata/key_server.pem", "Server TLS key file")
	clientCertFile = flag.String("client_cert_file", "testdata/cert_client3.pem", "Client1 TLS cert file for Auth")
	clientKeyFile  = flag.String("client_key_file", "testdata/key_client3.pem", "Client TLS key file")
)

// Gluecode logic
type Logic struct {
	// Wrap gRPC without much overhead or redirections
	server.Server
	// Good place for persisting own data
}

// SayHello implements helloworld.GreeterServer
func (s *Logic) SayHello(ctx context.Context, in *proto.HelloRequest) (*proto.HelloReply, error) {
	// log.Println("Received request while server context:", s.ctx)
	auth, ok := authentication.FromAuthContext(ctx)
	if !ok {
		return nil, fmt.Errorf("Failed to get authentication info from ctx")
	}

	return &proto.HelloReply{Message: fmt.Sprintf("Hello %#v (%s) with birthday on %#v", auth.PeerID, in.Name, in.Birth)}, nil
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
		// pbPairing.RegisterPairingServer(g, allServer)
		go func() {
			log.Println("Main server: waiting for pairings")
			registered := allServer.Pairing.IncomingRequests()
			for {
				select {
				case pID := <-registered:
					log.Println("Incoming registration from:", pID.Fingerprint())
					pID.Accept()
				}
			}

		}()

		// Serve blocks infinitely
		allServer.Serve()
		log.Println("Serve() stopped")

	}

}

func testClient() {
	const peerID = "gw4242.flexsmc.local"
	log.Println("Running client...")

	tlsKeyPrim := client.TLSKeyFile(*clientCertFile, *clientKeyFile)
	cl := client.NewClient(tlsKeyPrim)
	defer cl.TearDown()

	// modPair := pairing.NewApprovalPairing(cl.GetPeerCerts())

	// Pairing
	connP, err := cl.DialUnsecure(peerID)
	if err != nil {
		panic(err)
	}
	pr := pairing.NewClientApproval(cl.GetPeerCerts(), connP)
	ctx2, _ := context.WithTimeout(context.Background(), time.Second)
	gwIdentity, err := pr.StartPairing(ctx2, nil)
	if err != nil {
		panic(err)
	}
	log.Println("GWIdentity:", gwIdentity.Fingerprint())
	gwIdentity.Accept()

	// conR := pbPairing.NewPairingClient(connP)
	// resp, err := conR.Register(context.Background(), &pbPairing.RegisterRequest{Name: "It's me"})
	// fmt.Println("Pairing Resp:", resp, " ERR:", err)

	// Regular RPC calls
	conn, err := cl.Dial(peerID)
	if err != nil {
		panic(err)
	}

	// Do a registration
	// conR := pbPairing.NewPairingClient(conn)
	// resp, err := conR.Register(context.Background(), &pbPairing.RegisterRequest{Name: "It's me"})
	// if err != nil {
	// 	log.Printf("could not register: %v", err)
	// } else {
	// 	log.Printf("[%d] Register Status: %d", -1, resp.Status)
	// }
	conT := proto.NewGreeterClient(conn)
	for i := 0; i < 3; i++ {
		resp, err := conT.SayHello(context.Background(), &proto.HelloRequest{Name: "Ms.RPC", Birth: &proto.CalenderDay{Year: 1991, Month: 42, Day: 42}})
		if err != nil {
			log.Fatalf("could not greet: %v", err)
		}
		log.Printf("[%d] Greeting: %s", i, resp.Message)

	}
}
