package server

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
	// The function to execute on a request.
	// If nil, the default handler is executed for a routed entry. Catch-all
	// entries must implement a handler function.
	Func grpc.UnaryServerInterceptor
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
	// Catch-all case: call interceptor for all methods that are not
	// consumed by one of the preceding interceptors
	if d.FullMethod[0] == "*" && d.Func != nil {
		ci.catchAll = append(ci.catchAll, d)
	}
	// Everything else is routed to the function given
	for _, m := range d.FullMethod {
		if _, exists := ci.directed[m]; exists {
			return fmt.Errorf("interceptor with method `%s` already exists", m)
		}
		ci.directed[m] = d
	}
	return nil
}

func (ci *RoutedInterceptor) Invoke(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	// Routed interceptions
	if i, ok := ci.directed[info.FullMethod]; ok {
		log.Println("Directed interceptor:", i)
		if i.Func != nil {
			resp, err = i.Func(ctx, req, info, handler)
		} else {
			resp, err = handler(ctx, req)
		}
		if i.Consume {
			return
		}
	}
	// Catch-all interceptions
	// XXX: only the last one defines the response right now! Ctx is ok
	for _, i := range ci.catchAll {
		// TODO: adapt to chain multiple handlers
		log.Println("Catchall interceptor:", i)
		resp, err = i.Func(ctx, req, info, handler)

		if i.Consume {
			return
		}
	}
	// End of chain: default handler as fallback
	resp, err = handler(ctx, req)
	return
}
