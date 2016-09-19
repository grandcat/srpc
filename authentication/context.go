package authentication

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type ContextualServerStream struct {
	// Embed ServerStream
	grpc.ServerStream
	// Additional context
	Ctx context.Context
}

// NewContextualServerStream wraps gRPC's ServerStream and attaches a mutable context.
func NewContextualServerStream(ss grpc.ServerStream) *ContextualServerStream {
	return &ContextualServerStream{
		ServerStream: ss,
		Ctx:          ss.Context(),
	}
}

// Context returns the embedded context associated with a gRPC ServerStream.
// It overwrites the Context() from the embedded ServerStream instance. By this,
// we can alter the context and pass additional information for authentication.
func (cs *ContextualServerStream) Context() context.Context {
	return cs.Ctx
}
