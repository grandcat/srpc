package registry

import (
	"errors"
	"log"
	"net"

	"strings"

	zeroconf "github.com/grandcat/zeroconf.sd"
	"google.golang.org/grpc/naming"
)

var errNoMoreUpdates = errors.New("zeroconf: no more updates")

type ServiceDiscovery struct {
	mdns *zeroconf.Resolver
}

func NewServiceDiscovery() *ServiceDiscovery {
	mdns, err := zeroconf.NewResolver(nil)
	if err != nil {
		panic("could not init mDNS Resolver")
	}

	log.Printf("Zeroconf Service Discovery started.")
	return &ServiceDiscovery{
		mdns: mdns,
	}
}

func (sd *ServiceDiscovery) Resolve(target string) (naming.Watcher, error) {
	entries := make(chan *zeroconf.ServiceEntry)
	// XXX: replace hardcoded service and domain names
	target = strings.TrimSuffix(target, ".flexsmc.local")
	if err := sd.mdns.Lookup(target, "_flexsmc._tcp", "", entries); err != nil {
		return nil, err
	}

	return &mdnsWatcher{
		target:  target,
		updates: entries,
		done:    make(chan struct{}),
	}, nil
}

type mdnsWatcher struct {
	target       string
	updates      <-chan *zeroconf.ServiceEntry
	markedForDel []*naming.Update
	done         chan struct{}
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

	case <-w.done:
		log.Printf("[%s] mdnsWatcher stopped", w.target)
		return nil, errNoMoreUpdates
	}

	return results, nil
}

func (w *mdnsWatcher) Close() {
	close(w.done)
}
