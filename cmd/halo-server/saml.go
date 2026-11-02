package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/server"
)

// samlOptions are the --saml-* flags (ADR-0039). SAML is on when an IdP
// metadata file or URL is given.
type samlOptions struct {
	metadataFile, metadataURL string
	keyFile, certFile         string
	entityID, userAttr        string
	groupsAttrs               string
	allowIdPInitiated         bool
}

func samlFlags(fs *flag.FlagSet, o *samlOptions) {
	fs.StringVar(&o.metadataFile, "saml-idp-metadata-file", "", "IdP SAML metadata XML file; enables SAML login at /auth/saml/login next to OIDC (ADR-0039)")
	fs.StringVar(&o.metadataURL, "saml-idp-metadata-url", "", "IdP SAML metadata URL (https), fetched at start instead of --saml-idp-metadata-file; restart to pick up a rotated IdP certificate")
	fs.StringVar(&o.keyFile, "saml-sp-key-file", "", "PEM private key (RSA or ECDSA) of the SAML service provider: signs AuthnRequests, decrypts encrypted assertions")
	fs.StringVar(&o.certFile, "saml-sp-cert-file", "", "PEM certificate of --saml-sp-key-file, published in the SP metadata at /auth/saml/metadata")
	fs.StringVar(&o.entityID, "saml-entity-id", "", "SAML SP entity ID, the audience assertions must name (default <baseURL>/auth/saml/metadata)")
	fs.StringVar(&o.userAttr, "saml-user-attribute", "", "assertion attribute holding the user id (default: the NameID)")
	fs.StringVar(&o.groupsAttrs, "saml-groups-attribute", "", "comma-separated assertion attributes holding groups (default: "+strings.Join(server.DefaultSAMLGroupsAttributes, ", ")+")")
	fs.BoolVar(&o.allowIdPInitiated, "saml-allow-idp-initiated", false, "accept IdP-initiated (unsolicited) SAML responses; off by default: they cannot be bound to the browser that logs in")
}

func (o samlOptions) on() bool { return o.metadataFile != "" || o.metadataURL != "" }

func (o samlOptions) validate() error {
	switch {
	case o.metadataFile != "" && o.metadataURL != "":
		return errors.New("use only one of --saml-idp-metadata-file and --saml-idp-metadata-url")
	case o.on() && (o.keyFile == "" || o.certFile == ""):
		return errors.New("SAML login requires --saml-sp-key-file and --saml-sp-cert-file")
	case !o.on() && (o.keyFile != "" || o.certFile != "" || o.entityID != "" || o.userAttr != "" || o.groupsAttrs != "" || o.allowIdPInitiated):
		return errors.New("--saml-* flags need --saml-idp-metadata-file or --saml-idp-metadata-url")
	}
	return nil
}

// config reads the files (and fetches the metadata URL); nil when SAML is off.
func (o samlOptions) config(ctx context.Context) (*server.SAMLConfig, error) {
	if !o.on() {
		return nil, nil
	}
	c := &server.SAMLConfig{EntityID: o.entityID, UserAttribute: o.userAttr, GroupsAttributes: splitCSV(o.groupsAttrs), AllowIdPInitiated: o.allowIdPInitiated}
	var err error
	if o.metadataFile != "" {
		if c.IdPMetadata, err = os.ReadFile(o.metadataFile); err != nil {
			return nil, fmt.Errorf("--saml-idp-metadata-file: %w", err)
		}
	} else if c.IdPMetadata, err = fetchSAMLMetadata(ctx, o.metadataURL); err != nil {
		return nil, fmt.Errorf("--saml-idp-metadata-url: %w", err)
	}
	b, err := os.ReadFile(o.keyFile)
	if err != nil {
		return nil, fmt.Errorf("--saml-sp-key-file: %w", err)
	}
	if c.Key, err = parsePEMKey(b); err != nil {
		return nil, fmt.Errorf("--saml-sp-key-file: %w", err)
	}
	if b, err = os.ReadFile(o.certFile); err != nil {
		return nil, fmt.Errorf("--saml-sp-cert-file: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("--saml-sp-cert-file: no PEM CERTIFICATE block")
	}
	if c.Cert, err = x509.ParseCertificate(blk.Bytes); err != nil {
		return nil, fmt.Errorf("--saml-sp-cert-file: %w", err)
	}
	if c.AllowIdPInitiated {
		slog.Warn("--saml-allow-idp-initiated: unsolicited SAML responses are accepted; they cannot be bound to the browser that logs in (ADR-0039)")
	}
	return c, nil
}

// parsePEMKey reads a PKCS#8, PKCS#1 (RSA) or SEC 1 (EC) PEM private key.
func parsePEMKey(b []byte) (crypto.Signer, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	var k any
	var err error
	switch blk.Type {
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(blk.Bytes)
	default:
		k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	}
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T", k)
	}
	return s, nil
}

// fetchSAMLMetadata GETs IdP metadata: https only (http to loopback for
// tests), 10-second timeout, no redirects, at most 1 MiB.
func fetchSAMLMetadata(ctx context.Context, raw string) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%q is not an absolute URL", raw)
	}
	ip := net.ParseIP(u.Hostname())
	loopback := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Scheme != "https" && (u.Scheme != "http" || !loopback) {
		return nil, fmt.Errorf("%q must be https (http only to loopback)", raw)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", raw, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("metadata larger than 1 MiB")
	}
	return b, nil
}
