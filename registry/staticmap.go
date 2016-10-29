package registry

import (
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc/naming"
)

const (
	uriSuffix = ".local"

	resolvWaitTime = 1 * time.Second
)

var (
	targetAddr = map[string]string{
		"gw4242.flexsmc.local": "[::1]:50051",
	}
)

// StaticAddrMap provides a resolution service for gRPC naming interface to statically
// link local mDNS domains to the targeted service reachable through a set IP and port.
type StaticAddrMap struct {
}

// Resolve creates a Watcher object for a target to track its resolution changes
func (sam *StaticAddrMap) Resolve(target string) (naming.Watcher, error) {
	// Check responsibility
	if !(strings.HasSuffix(target, uriSuffix)) {
		return nil, fmt.Errorf("StaticAddrMap resolver can only handle URIs ending with %s", uriSuffix)
	}

	ctx, cancel := context.WithCancel(context.Background())

	log.Println("new StaticAddrMap resolver requested")
	w := &resolvWatcher{
		target: target,
		ctx:    ctx,
		cancel: cancel,
		done:   false,
	}

	return w, nil
}

// resolvWatcher implements naming.Watcher
type resolvWatcher struct {
	target string
	ctx    context.Context
	cancel context.CancelFunc

	done bool
}

func (rw *resolvWatcher) Next() ([]*naming.Update, error) {
	log.Printf("Starting to resolv. Consumes %v from now on", resolvWaitTime)

	if err := rw.ctx.Err(); err != nil {
		log.Printf("Resolver: %v", err.Error())
		return nil, err
	}
	// Simulate some prcessing time to resolv the addr
	time.Sleep(resolvWaitTime)

	// Try to match with static address mapping table
	addr, ok := targetAddr[rw.target]

	if ok && !rw.done {
		rw.done = true

		res := []*naming.Update{&naming.Update{
			Op:   naming.Add,
			Addr: addr,
		}}
		log.Printf("StaticAddrMap: resolving %s to %s \n", rw.target, res[0].Addr)

		return res, nil

	}

	return make([]*naming.Update, 0), nil
}

func (rw *resolvWatcher) Close() {
	rw.cancel()
}
