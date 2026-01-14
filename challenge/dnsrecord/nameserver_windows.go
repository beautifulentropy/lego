//go:build windows

package dnsrecord

import "time"

// dnsTimeout is used to override the default DNS timeout of 20 seconds.
var dnsTimeout = 20 * time.Second
