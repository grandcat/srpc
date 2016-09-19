package srpc

import (
	"fmt"
	"log"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type UnaryInterceptInfo struct {
	// Methods that trigger this interception handler.
	FullMethod []string
	// If there are multiple interceptors for the regarded method string,
	// a handler is passed along a chaing of interceptors until one party
	// consumes it. In this case, interception ends here.
	// Last, it will stop at the end of the chain.
	Consume bool
	// The function to execute on an unary request.
	// If nil, the default handler is executed for a routed entry. Catch-all
	// entries must implement a handler function.
	UnaryFunc grpc.UnaryServerInterceptor
	// The function to execute for a stream.
	StreamFunc grpc.StreamServerInterceptor
}

var GlobalRoutedInterceptor = NewRoutedInterceptor()

type RoutedInterceptor struct {
	directed map[string]UnaryInterceptInfo
	catchAll []UnaryInterceptInfo
}

func NewRoutedInterceptor() *RoutedInterceptor {
	return &RoutedInterceptor{
		directed: make(map[string]UnaryInterceptInfo),
	}
}

// Add integrates new routed or catch-all interceptors.
func (ci *RoutedInterceptor) Add(d UnaryInterceptInfo) error {
	if len(d.FullMethod) == 0 {
		return nil
	}
	for _, m := range d.FullMethod {
		if m == "*" {
			// Catch-all case: call interceptor for all methods that are not
			// consumed by one of the preceding interceptors
			if d.UnaryFunc == nil {
				return fmt.Errorf("no func provided for catch-all interceptor")
			}
			ci.catchAll = append(ci.catchAll, d)

		} else {
			// Everything else is routed to the function given
			if _, exists := ci.directed[m]; exists {
				return fmt.Errorf("interceptor with method `%s` already exists", m)
			}
			ci.directed[m] = d
		}
	}

	return nil
}

func (ci *RoutedInterceptor) AddMultiple(ds []UnaryInterceptInfo) error {
	for _, d := range ds {
		if e := ci.Add(d); e != nil {
			return e
		}
	}
	return nil
}

func (ci *RoutedInterceptor) InvokeUnary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	// Routed interceptions
	if i, ok := ci.directed[info.FullMethod]; ok {
		log.Println("[Unary] Directed interceptor:", i)
		if i.UnaryFunc != nil {
			resp, err = i.UnaryFunc(ctx, req, info, handler)
		} else {
			resp, err = handler(ctx, req)
		}
		if i.Consume {
			return
		}
	}
	// Unary catch-all interceptions
	// XXX: only the last one defines the response right now! Ctx is ok
	for _, i := range ci.catchAll {
		// TODO: adapt to chain multiple handlers
		log.Println("[Unary] Catchall interceptor:", i)
		if i.UnaryFunc != nil {
			resp, err = i.UnaryFunc(ctx, req, info, handler)
		}

		if i.Consume {
			return
		}
	}
	// End of chain: default handler as fallback
	resp, err = handler(ctx, req)
	return
}

func (ci *RoutedInterceptor) InvokeStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	// Routed stream interceptions
	if i, ok := ci.directed[info.FullMethod]; ok {
		log.Println("[Stream] Directed interceptor:", i)
		if i.StreamFunc != nil {
			err = i.StreamFunc(srv, ss, info, handler)
		} else {
			err = handler(srv, ss)
		}
		if i.Consume {
			return
		}
	}
	// Stream catch-all interceptions
	// XXX: only the last one defines the response right now! Ctx is ok
	for _, i := range ci.catchAll {
		log.Println("[Stream] Catchall interceptor:", i)
		if i.StreamFunc != nil {
			err = i.StreamFunc(srv, ss, info, handler)
		}

		if i.Consume {
			return
		}
	}
	// End of chain: default (last) handler as fallback
	err = handler(srv, ss)
	return
}
