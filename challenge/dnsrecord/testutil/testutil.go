package testutil

import "github.com/go-acme/lego/v4/challenge/dnsrecord"

// ClearFqdnCache clears the cache of fqdn to zone mappings. Primarily used in testing.
func ClearFqdnCache() {
	dnsrecord.ClearFqdnCache()
}
