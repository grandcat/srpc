package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	gtypeAny "github.com/golang/protobuf/ptypes/any"
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

	return &proto.HelloReply{Message: fmt.Sprintf("Hello %#v (%s) with birthday on %#v", auth.ID, in.Name, in.Birth)}, nil
}

func main() {
	flag.Parse()

	if *isClient {
		testClient()

	} else {
		// Configure server and gRPC options
		tlsKeyPrim := server.TLSKeyFile(*certFile, *keyFile)
		allServer := &Logic{server.NewServer(tlsKeyPrim)}
		// Register pairing module
		mPairing := pairing.NewServerApproval(allServer.PeerCerts(), gtypeAny.Any{"flexsmc/peerinfo", []byte{1, 2, 3}})
		allServer.RegisterModules(mPairing)
		// myServer := LogicEntity(baseServer)
		// innerServer := server.Serverize(myServer)
		// innerServer := server.Serverize(allServer)
		// g, _ := server.Prepare(server.Serverize(allServer))

		g, err := allServer.Build()
		if err != nil {
			panic(err)
		}
		proto.RegisterGreeterServer(g, allServer)
		// pbPairing.RegisterPairingServer(g, allServer)
		go func() {
			log.Println("Main server: waiting for pairings")
			registered := mPairing.IncomingRequests()
			for {
				select {
				case pID := <-registered:
					log.Println("Incoming registration from:", pID.Fingerprint(), "with details:", pID.Details())
					time.Sleep(time.Second * 5) //< Simulate an out-of-band verification. Takes some time...
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

	// modPair := pairing.NewApprovalPairing(cl.PeerCerts())

	// Pairing
	connP, err := cl.DialUnsecure(peerID)
	if err != nil {
		panic(err)
	}
	pr := pairing.NewClientApproval(cl.PeerCerts(), connP)
	ctx2, _ := context.WithTimeout(context.Background(), 10*time.Second)
	gwIdentity, err := pr.StartPairing(ctx2, &gtypeAny.Any{"flexsmc/peerinfo", []byte{3, 4, 5}})
	if err != nil {
		panic(err)
	}
	log.Println("GWIdentity:", gwIdentity.Fingerprint(), "GWDetails:", gwIdentity.Details())
	gwIdentity.Accept()
	// Wait for server to accept our pairing request
	prStatus := pr.AwaitPairingResult(ctx2)
	if r, ok := <-prStatus; ok {
		log.Println("Pairing: peer responded with", r)
	} else {
		log.Println("Pairing aborted by peer")
	}

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
