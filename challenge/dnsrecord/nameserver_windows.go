//go:build windows

package dnsrecord

import "time"

// defaultDNSTimeout is used as the default DNS timeout on Windows.
const defaultDNSTimeout = 20 * time.Second
