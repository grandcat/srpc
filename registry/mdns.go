package registry

import (
	"errors"
	"log"
	"net"

	"strings"

	"context"

	zeroconf "github.com/grandcat/zeroconf.sd"
	"google.golang.org/grpc/naming"
)

var errNoMoreUpdates = errors.New("zeroconf: no more updates")

type ServiceDiscovery struct {
	mdns *zeroconf.Resolver
}

func NewServiceDiscovery() *ServiceDiscovery {
	ipv6only := zeroconf.SelectIPTraffic(zeroconf.IPv6)
	mdns, err := zeroconf.NewResolver(ipv6only)
	if err != nil {
		panic("could not init mDNS Resolver")
	}

	log.Printf("Zeroconf Service Discovery started.")
	return &ServiceDiscovery{
		mdns: mdns,
	}
}

func (sd *ServiceDiscovery) Resolve(target string) (naming.Watcher, error) {
	ctx, cancel := context.WithCancel(context.Background())
	entries := make(chan *zeroconf.ServiceEntry)
	// XXX: replace hardcoded service and domain names
	target = strings.TrimSuffix(target, ".flexsmc.local")
	if err := sd.mdns.Lookup(ctx, target, "_flexsmc._tcp", "", entries); err != nil {
		cancel()
		return nil, err
	}

	return &mdnsWatcher{
		ctx:          ctx,
		target:       target,
		updates:      entries,
		cancelLookup: cancel,
	}, nil
}

type mdnsWatcher struct {
	ctx          context.Context
	target       string
	updates      <-chan *zeroconf.ServiceEntry
	markedForDel []*naming.Update
	cancelLookup context.CancelFunc
}

func (w *mdnsWatcher) Next() ([]*naming.Update, error) {
	// Assume that the requester queries for a concrete instance, rather for a whole
	// service group. Therefore, any new result will replace an old one.
	var results = w.markedForDel
	w.markedForDel = nil

	log.Printf("[%s] mdnsWatcher: Next entered", w.target)

	select {
	case s, more := <-w.updates:
		if !more {
			return nil, errNoMoreUpdates
		}
		log.Println(s)
		// Extract all IPs for this service. Prefer IPv6 over IPv4.
		// Also add to marked entries to be removed next time if a new update arrives.
		for _, ip := range s.AddrIPv6 {
			tcpAddr := net.TCPAddr{IP: ip, Port: s.Port}
			addr := tcpAddr.String()
			results = append(results, &naming.Update{Op: naming.Add, Addr: addr})
			w.markedForDel = append(w.markedForDel, &naming.Update{Op: naming.Delete, Addr: addr})
		}
		for _, ip := range s.AddrIPv4 {
			tcpAddr := net.TCPAddr{IP: ip, Port: s.Port}
			addr := tcpAddr.String()
			results = append(results, &naming.Update{Op: naming.Add, Addr: addr})
			w.markedForDel = append(w.markedForDel, &naming.Update{Op: naming.Delete, Addr: addr})
		}
		log.Printf("Extracted IPs: %v", results)

	case <-w.ctx.Done():
		log.Printf("[%s] mdnsWatcher stopped", w.target)
		return nil, errNoMoreUpdates
	}

	return results, nil
}

func (w *mdnsWatcher) Close() {
	w.cancelLookup()
}
