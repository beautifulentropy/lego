package dnspersist01

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/platform/tester/dnsmock"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_preCheck_checkDNSPropagation(t *testing.T) {
	addr := dnsmock.NewServer().
		Query("ns0.lego.localhost. A",
			dnsmock.Answer(fakeA("ns0.lego.localhost.", "127.0.0.1"))).
		Query("ns1.lego.localhost. A",
			dnsmock.Answer(fakeA("ns1.lego.localhost.", "127.0.0.1"))).
		Query("example.com. TXT",
			dnsmock.Answer(
				fakeTXT("example.com.", "one", 10),
				fakeTXT("example.com.", "two", 10),
				fakeTXT("example.com.", "three", 10),
				fakeTXT("example.com.", "four", 10),
				fakeTXT("example.com.", "five", 10),
			),
		).
		Query("acme-staging.api.example.com. TXT",
			dnsmock.Answer(
				fakeTXT("acme-staging.api.example.com.", "one", 10),
				fakeTXT("acme-staging.api.example.com.", "two", 10),
				fakeTXT("acme-staging.api.example.com.", "three", 10),
				fakeTXT("acme-staging.api.example.com.", "four", 10),
				fakeTXT("acme-staging.api.example.com.", "five", 10),
			),
		).
		Query("acme-staging.api.example.com. SOA", dnsmock.Error(dns.RcodeNameError)).
		Query("api.example.com. SOA", dnsmock.Error(dns.RcodeNameError)).
		Query("example.com. SOA", dnsmock.SOA("")).
		Query("example.com. NS",
			dnsmock.Answer(
				fakeNS("example.com.", "ns0.lego.localhost."),
				fakeNS("example.com.", "ns1.lego.localhost."),
			),
		).
		Build(t)

	mockResolver(t, addr)
	useAsNameserver(t, addr)

	resolver := NewResolver([]string{addr.String()})
	chlg := &Challenge{resolver: resolver, preCheck: newPreCheck()}

	testCases := []struct {
		desc          string
		fqdn          string
		value         string
		expectedError bool
	}{
		{
			desc:  "success",
			fqdn:  "example.com.",
			value: "four",
		},
		{
			desc:          "no matching TXT record",
			fqdn:          "acme-staging.api.example.com.",
			value:         "fe01=",
			expectedError: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			match := func(records []TXTRecord) bool {
				for _, record := range records {
					if record.Value == test.value {
						return true
					}
				}

				return false
			}

			ok, err := chlg.checkDNSPropagation(test.fqdn, match)
			if test.expectedError {
				require.Error(t, err)
				assert.False(t, ok)
			} else {
				require.NoError(t, err)
				assert.True(t, ok)
			}
		})
	}
}

func fakeNS(name, ns string) *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800},
		Ns:  ns,
	}
}

func fakeA(name, ip string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
		A:   net.ParseIP(ip),
	}
}

// mockResolver modifies the default DNS resolver to use a custom network address during the test execution.
// IMPORTANT: it modifies global variables.
func mockResolver(t *testing.T, addr net.Addr) {
	t.Helper()

	_, port, err := net.SplitHostPort(addr.String())
	require.NoError(t, err)

	originalDefaultNameserverPort := defaultNameserverPort

	t.Cleanup(func() {
		defaultNameserverPort = originalDefaultNameserverPort
	})

	defaultNameserverPort = port

	originalResolver := net.DefaultResolver

	t.Cleanup(func() {
		net.DefaultResolver = originalResolver
	})

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 1 * time.Second}

			return d.DialContext(ctx, network, addr.String())
		},
	}
}

func useAsNameserver(t *testing.T, addr net.Addr) {
	t.Helper()

	originalRecursiveNameservers := recursiveNameservers

	t.Cleanup(func() {
		recursiveNameservers = originalRecursiveNameservers
	})

	recursiveNameservers = ParseNameservers([]string{addr.String()})
}
