package cmd

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/dnspersist01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/providers/http/memcached"
	"github.com/go-acme/lego/v4/providers/http/s3"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/urfave/cli/v2"
)

func setupChallenges(ctx *cli.Context, client *lego.Client, account *Account) {
	if !ctx.Bool(flgHTTP) && !ctx.Bool(flgTLS) && !ctx.IsSet(flgDNS) && !ctx.Bool(flgDNSPersist) {
		log.Fatalf("No challenge selected. You must specify at least one challenge: `--%s`, `--%s`, `--%s`, `--%s`.", flgHTTP, flgTLS, flgDNS, flgDNSPersist)
	}

	if ctx.Bool(flgHTTP) {
		err := client.Challenge.SetHTTP01Provider(setupHTTPProvider(ctx), http01.SetDelay(ctx.Duration(flgHTTPDelay)))
		if err != nil {
			log.Fatal(err)
		}
	}

	if ctx.Bool(flgTLS) {
		err := client.Challenge.SetTLSALPN01Provider(setupTLSProvider(ctx), tlsalpn01.SetDelay(ctx.Duration(flgTLSDelay)))
		if err != nil {
			log.Fatal(err)
		}
	}

	if ctx.IsSet(flgDNS) {
		err := setupDNS(ctx, client)
		if err != nil {
			log.Fatal(err)
		}
	}

	if ctx.Bool(flgDNSPersist) {
		err := setupDNSPersist(ctx, client, account)
		if err != nil {
			log.Fatal(err)
		}
	}
}

//nolint:gocyclo // the complexity is expected.
func setupHTTPProvider(ctx *cli.Context) challenge.Provider {
	switch {
	case ctx.IsSet(flgHTTPWebroot):
		ps, err := webroot.NewHTTPProvider(ctx.String(flgHTTPWebroot))
		if err != nil {
			log.Fatal(err)
		}

		return ps
	case ctx.IsSet(flgHTTPMemcachedHost):
		ps, err := memcached.NewMemcachedProvider(ctx.StringSlice(flgHTTPMemcachedHost))
		if err != nil {
			log.Fatal(err)
		}

		return ps
	case ctx.IsSet(flgHTTPS3Bucket):
		ps, err := s3.NewHTTPProvider(ctx.String(flgHTTPS3Bucket))
		if err != nil {
			log.Fatal(err)
		}

		return ps
	case ctx.IsSet(flgHTTPPort):
		iface := ctx.String(flgHTTPPort)
		if !strings.Contains(iface, ":") {
			log.Fatalf("The --%s switch only accepts interface:port or :port for its argument.", flgHTTPPort)
		}

		host, port, err := net.SplitHostPort(iface)
		if err != nil {
			log.Fatal(err)
		}

		srv := http01.NewProviderServer(host, port)
		if header := ctx.String(flgHTTPProxyHeader); header != "" {
			srv.SetProxyHeader(header)
		}

		return srv
	case ctx.Bool(flgHTTP):
		srv := http01.NewProviderServer("", "")
		if header := ctx.String(flgHTTPProxyHeader); header != "" {
			srv.SetProxyHeader(header)
		}

		return srv
	default:
		log.Fatal("Invalid HTTP challenge options.")
		return nil
	}
}

func setupTLSProvider(ctx *cli.Context) challenge.Provider {
	switch {
	case ctx.IsSet(flgTLSPort):
		iface := ctx.String(flgTLSPort)
		if !strings.Contains(iface, ":") {
			log.Fatalf("The --%s switch only accepts interface:port or :port for its argument.", flgTLSPort)
		}

		host, port, err := net.SplitHostPort(iface)
		if err != nil {
			log.Fatal(err)
		}

		return tlsalpn01.NewProviderServer(host, port)
	case ctx.Bool(flgTLS):
		return tlsalpn01.NewProviderServer("", "")
	default:
		log.Fatal("Invalid HTTP challenge options.")
		return nil
	}
}

func setupDNS(ctx *cli.Context, client *lego.Client) error {
	err := checkDNSPropagationExclusiveOptions(ctx)
	if err != nil {
		return err
	}

	wait := ctx.Duration(flgDNSPropagationWait)
	if wait < 0 {
		return fmt.Errorf("'%s' cannot be negative", flgDNSPropagationWait)
	}

	provider, err := dns.NewDNSChallengeProviderByName(ctx.String(flgDNS))
	if err != nil {
		return err
	}

	servers := ctx.StringSlice(flgDNSResolvers)

	err = client.Challenge.SetDNS01Provider(provider,
		dns01.CondOption(len(servers) > 0,
			dns01.AddRecursiveNameservers(dns01.ParseNameservers(ctx.StringSlice(flgDNSResolvers)))),

		dns01.CondOption(ctx.Bool(flgDNSDisableCP) || ctx.Bool(flgDNSPropagationDisableANS),
			dns01.DisableAuthoritativeNssPropagationRequirement()),

		dns01.CondOption(ctx.Duration(flgDNSPropagationWait) > 0,
			// TODO(ldez): inside the next major version we will use flgDNSDisableCP here.
			// This will change the meaning of this flag to really disable all propagation checks.
			dns01.PropagationWait(wait, true)),

		dns01.CondOption(ctx.Bool(flgDNSPropagationRNS),
			dns01.RecursiveNSsPropagationRequirement()),

		dns01.CondOption(ctx.IsSet(flgDNSTimeout),
			dns01.AddDNSTimeout(time.Duration(ctx.Int(flgDNSTimeout))*time.Second)),
	)

	return err
}

func checkDNSPersistPropagationExclusiveOptions(ctx *cli.Context) error {
	if isSetBool(ctx, flgDNSPersistPropagationDisableANS) && ctx.IsSet(flgDNSPersistPropagationWait) {
		return fmt.Errorf("'%s' and '%s' are mutually exclusive", flgDNSPersistPropagationDisableANS, flgDNSPersistPropagationWait)
	}

	if isSetBool(ctx, flgDNSPersistPropagationRNS) && ctx.IsSet(flgDNSPersistPropagationWait) {
		return fmt.Errorf("'%s' and '%s' are mutually exclusive", flgDNSPersistPropagationRNS, flgDNSPersistPropagationWait)
	}

	return nil
}

func setupDNSPersist(ctx *cli.Context, client *lego.Client, account *Account) error {
	if account == nil || account.Registration == nil {
		return fmt.Errorf("dns-persist-01 requires a registered account with an account URI")
	}
	accountURI := account.Registration.URI
	if accountURI == "" {
		return fmt.Errorf("dns-persist-01 requires a registered account with an account URI")
	}

	err := checkDNSPersistPropagationExclusiveOptions(ctx)
	if err != nil {
		return err
	}

	wait := ctx.Duration(flgDNSPersistPropagationWait)
	if wait < 0 {
		return fmt.Errorf("'%s' cannot be negative", flgDNSPersistPropagationWait)
	}

	opts := []dnspersist01.ChallengeOption{dnspersist01.WithAccountURI(accountURI)}

	if ctx.String(flgDNSPersistIssuerDomainName) != "" {
		opts = append(opts, dnspersist01.WithIssuerDomainName(ctx.String(flgDNSPersistIssuerDomainName)))
	}
	if ctx.IsSet(flgDNSPersistPersistUntil) {
		persistUntil, err := time.Parse(time.RFC3339, ctx.String(flgDNSPersistPersistUntil))
		if err != nil {
			return fmt.Errorf("invalid value for '%s': must be RFC3339: %w", flgDNSPersistPersistUntil, err)
		}

		opts = append(opts, dnspersist01.WithPersistUntil(persistUntil))
	}

	if ctx.IsSet(flgDNSPersistResolvers) {
		resolvers := ctx.StringSlice(flgDNSPersistResolvers)
		if len(resolvers) > 0 {
			opts = append(opts, dnspersist01.WithNameservers(resolvers))
			opts = append(opts, dnspersist01.AddRecursiveNameservers(resolvers))
		}
	}

	if ctx.IsSet(flgDNSPersistTimeout) {
		timeout := time.Duration(ctx.Int(flgDNSPersistTimeout)) * time.Second
		opts = append(opts, dnspersist01.WithDNSTimeout(timeout))
	}

	if ctx.Bool(flgDNSPersistPropagationDisableANS) {
		opts = append(opts, dnspersist01.DisableAuthoritativeNssPropagationRequirement())
	}

	if ctx.Bool(flgDNSPersistPropagationRNS) {
		opts = append(opts, dnspersist01.RecursiveNSsPropagationRequirement())
	}

	if ctx.Duration(flgDNSPersistPropagationWait) > 0 {
		opts = append(opts, dnspersist01.PropagationWait(wait, true))
	}

	return client.Challenge.SetDNSPersist01(opts...)
}

func checkDNSPropagationExclusiveOptions(ctx *cli.Context) error {
	if ctx.IsSet(flgDNSDisableCP) {
		log.Printf("The flag '%s' is deprecated use '%s' instead.", flgDNSDisableCP, flgDNSPropagationDisableANS)
	}

	if (isSetBool(ctx, flgDNSDisableCP) || isSetBool(ctx, flgDNSPropagationDisableANS)) && ctx.IsSet(flgDNSPropagationWait) {
		return fmt.Errorf("'%s' and '%s' are mutually exclusive", flgDNSPropagationDisableANS, flgDNSPropagationWait)
	}

	if isSetBool(ctx, flgDNSPropagationRNS) && ctx.IsSet(flgDNSPropagationWait) {
		return fmt.Errorf("'%s' and '%s' are mutually exclusive", flgDNSPropagationRNS, flgDNSPropagationWait)
	}

	return nil
}

func isSetBool(ctx *cli.Context, name string) bool {
	return ctx.IsSet(name) && ctx.Bool(name)
}
