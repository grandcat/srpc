package srpc

import "google.golang.org/grpc"

type ServerModule interface {
	RegisterServer(*grpc.Server)
	InterceptMethods() []UnaryInterceptInfo
}
