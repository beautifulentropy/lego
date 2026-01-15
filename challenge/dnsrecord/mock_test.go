package dnsrecord

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func fakeNS(name, ns string) *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800},
		Ns:  ns,
	}
}

func useAsNameserver(t *testing.T, addr net.Addr) {
	t.Helper()

	ClearFqdnCache()
	t.Cleanup(func() {
		ClearFqdnCache()
	})

	originalRecursiveNameservers := GetRecursiveNameservers()

	t.Cleanup(func() {
		SetRecursiveNameservers(originalRecursiveNameservers)
	})

	SetRecursiveNameservers([]string{addr.String()})
}
