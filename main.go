package main

import (
	"fmt"
	"log"
	"net"

	proto "github.com/grandcat/flexsmc/helloworld"
	"github.com/grandcat/flexsmc/server"
	"golang.org/x/net/context"
)

// type LogicEntity interface {
// 	server.Serverize
// }

type Logic struct {
	server.ServerContext
}

// SayHello implements helloworld.GreeterServer
func (s *Logic) SayHello(ctx context.Context, in *proto.HelloRequest) (*proto.HelloReply, error) {
	// log.Println("Received request while server context:", s.ctx)
	return &proto.HelloReply{Message: "Hello " + in.Name + " with birthday on " + fmt.Sprintf("%#v", in.Birth)}, nil
}

func main() {
	allServer := &Logic{server.NewServer()}
	// myServer := LogicEntity(baseServer)
	// innerServer := server.Serverize(myServer)
	innerServer := server.Serverize(allServer)
	g := server.Prepare(innerServer)

	proto.RegisterGreeterServer(g, allServer)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	g.Serve(lis)

}
