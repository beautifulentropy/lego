package dnschallenge

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dnspersist01"
	"github.com/go-acme/lego/v4/e2e/loader"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPersistBaseDomain = "persist.localhost"
	testPersistDomain     = "*." + testPersistBaseDomain
	testPersistIssuer     = "pebble.letsencrypt.org"

	testPersistCLIDomain         = "persist-cli.localhost"
	testPersistCLIWildcardDomain = "*." + testPersistCLIDomain
	testPersistCLIEmail          = "persist-e2e@example.com"
)

func setTXTRecord(t *testing.T, host, value string) {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"host":  host,
		"value": value,
	})
	require.NoError(t, err)

	resp, err := http.Post("http://localhost:8055/set-txt", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func clearTXTRecord(t *testing.T, host string) {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"host": host,
	})
	require.NoError(t, err)

	resp, err := http.Post("http://localhost:8055/clear-txt", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func createCLIAccountState(t *testing.T, email string) string {
	t.Helper()

	privateKey, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	require.NoError(t, err)

	user := &fakeUser{
		email:      email,
		privateKey: privateKey,
	}
	config := lego.NewConfig(user)
	config.CADirURL = "https://localhost:15000/dir"

	client, err := lego.NewClient(config)
	require.NoError(t, err)

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	require.NoError(t, err)
	require.NotEmpty(t, reg.URI)

	accountsRoot := filepath.Join(".lego", "accounts", "localhost_15000", email)
	keysPath := filepath.Join(accountsRoot, "keys")
	err = os.MkdirAll(keysPath, 0o700)
	require.NoError(t, err)

	err = saveAccountPrivateKey(filepath.Join(keysPath, email+".key"), privateKey)
	require.NoError(t, err)

	accountPath := filepath.Join(accountsRoot, "account.json")
	content, err := json.MarshalIndent(struct {
		Email        string                 `json:"email"`
		Registration *registration.Resource `json:"registration"`
	}{
		Email:        email,
		Registration: reg,
	}, "", "\t")
	require.NoError(t, err)

	err = os.WriteFile(accountPath, content, 0o600)
	require.NoError(t, err)

	return reg.URI
}

func saveAccountPrivateKey(path string, privateKey crypto.PrivateKey) error {
	return os.WriteFile(path, certcrypto.PEMEncode(privateKey), 0o600)
}

func TestChallengeDNSPersist_Client_Obtain(t *testing.T) {
	err := os.Setenv("LEGO_CA_CERTIFICATES", "../fixtures/certs/pebble.minica.pem")
	require.NoError(t, err)

	defer func() { _ = os.Unsetenv("LEGO_CA_CERTIFICATES") }()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Could not generate test key")

	user := &fakeUser{privateKey: privateKey}
	config := lego.NewConfig(user)
	config.CADirURL = "https://localhost:15000/dir"

	client, err := lego.NewClient(config)
	require.NoError(t, err)

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	require.NoError(t, err)
	require.NotEmpty(t, reg.URI)

	user.registration = reg

	txtHost := fmt.Sprintf("_validation-persist.%s", testPersistBaseDomain)
	txtValue := dnspersist01.BuildIssueValues(testPersistIssuer, reg.URI, true, nil)

	setTXTRecord(t, txtHost, txtValue)
	defer clearTXTRecord(t, txtHost)

	err = client.Challenge.SetDNSPersist01(
		dnspersist01.WithAccountURI(reg.URI),
		dnspersist01.WithNameservers([]string{":8053"}),
		dnspersist01.AddRecursiveNameservers([]string{":8053"}),
		dnspersist01.DisableAuthoritativeNssPropagationRequirement(),
	)
	require.NoError(t, err)

	privateKeyCSR, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Could not generate test key")

	request := certificate.ObtainRequest{
		Domains:    []string{testPersistDomain},
		Bundle:     true,
		PrivateKey: privateKeyCSR,
	}
	resource, err := client.Certificate.Obtain(request)
	require.NoError(t, err)

	require.NotNil(t, resource)
	assert.Equal(t, testPersistDomain, resource.Domain)
	assert.Regexp(t, `https://localhost:15000/certZ/[\w\d]{14,}`, resource.CertURL)
	assert.Regexp(t, `https://localhost:15000/certZ/[\w\d]{14,}`, resource.CertStableURL)
	assert.NotEmpty(t, resource.Certificate)
	assert.NotEmpty(t, resource.IssuerCertificate)
	assert.Empty(t, resource.CSR)
}

func TestChallengeDNSPersist_Run(t *testing.T) {
	loader.CleanLegoFiles()

	err := os.Setenv("LEGO_CA_CERTIFICATES", "../fixtures/certs/pebble.minica.pem")
	require.NoError(t, err)
	defer func() { _ = os.Unsetenv("LEGO_CA_CERTIFICATES") }()

	accountURI := createCLIAccountState(t, testPersistCLIEmail)
	require.NotEmpty(t, accountURI)

	txtHost := fmt.Sprintf("_validation-persist.%s", testPersistCLIDomain)
	txtValue := dnspersist01.BuildIssueValues(testPersistIssuer, accountURI, true, nil)

	setTXTRecord(t, txtHost, txtValue)
	defer clearTXTRecord(t, txtHost)

	err = load.RunLego(
		"-m", testPersistCLIEmail,
		"--accept-tos",
		"--dns-persist",
		"--dns-persist.resolvers", ":8053",
		"--dns-persist.propagation-disable-ans",
		"--dns-persist.issuer-domain-name", testPersistIssuer,
		"-s", "https://localhost:15000/dir",
		"-d", testPersistCLIWildcardDomain,
		"-d", testPersistCLIDomain,
		"run",
	)
	require.NoError(t, err)
}
