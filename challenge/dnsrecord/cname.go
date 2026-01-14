package dnsrecord

import (
	"strings"

	"github.com/miekg/dns"
)

// UpdateDomainWithCName FQDN with CNAME if any.
func UpdateDomainWithCName(r *dns.Msg, fqdn string) string {
	for _, rr := range r.Answer {
		if cn, ok := rr.(*dns.CNAME); ok {
			if strings.EqualFold(cn.Hdr.Name, fqdn) {
				return cn.Target
			}
		}
	}

	return fqdn
}
