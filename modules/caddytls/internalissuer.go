// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/sunbird1015/caddy/v2"
	"github.com/sunbird1015/caddy/v2/caddyconfig/caddyfile"
	"github.com/sunbird1015/certmagic"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(InternalIssuer{})
}

// InternalIssuer is a certificate issuer that generates
// certificates internally using a locally-configured
// CA which can be customized using the `pki` app.
type InternalIssuer struct {
	// The ID of the CA to use for signing. The default
	// CA ID is "local". The CA can be configured with the
	// `pki` app.
	CA string `json:"ca,omitempty"`

	// The validity period of certificates.
	Lifetime caddy.Duration `json:"lifetime,omitempty"`

	// If true, the root will be the issuer instead of
	// the intermediate. This is NOT recommended and should
	// only be used when devices/clients do not properly
	// validate certificate chains.
	SignWithRoot bool `json:"sign_with_root,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (InternalIssuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.issuance.internal",
		New: func() caddy.Module { return new(InternalIssuer) },
	}
}

// Provision sets up the issuer.
func (iss *InternalIssuer) Provision(ctx caddy.Context) error {
	return errors.New("deleted")
}

// IssuerKey returns the unique issuer key for the
// confgured CA endpoint.
func (iss InternalIssuer) IssuerKey() string {
	return ""
}

// Issue issues a certificate to satisfy the CSR.
func (iss InternalIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	return nil, errors.New("deleted")
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into iss.
//
//	... internal {
//	    ca       <name>
//	    lifetime <duration>
//	    sign_with_root
//	}
func (iss *InternalIssuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "ca":
				if !d.AllArgs(&iss.CA) {
					return d.ArgErr()
				}

			case "lifetime":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				iss.Lifetime = caddy.Duration(dur)

			case "sign_with_root":
				if d.NextArg() {
					return d.ArgErr()
				}
				iss.SignWithRoot = true

			}
		}
	}
	return nil
}

// customCertLifetime allows us to customize certificates that are issued
// by Smallstep libs, particularly the NotBefore & NotAfter dates.
type customCertLifetime time.Duration

func (d customCertLifetime) Modify(cert *x509.Certificate, _ provisioner.SignOptions) error {
	cert.NotBefore = time.Now()
	cert.NotAfter = cert.NotBefore.Add(time.Duration(d))
	return nil
}

const defaultInternalCertLifetime = 12 * time.Hour

// Interface guards
var (
	_ caddy.Provisioner               = (*InternalIssuer)(nil)
	_ certmagic.Issuer                = (*InternalIssuer)(nil)
	_ provisioner.CertificateModifier = (*customCertLifetime)(nil)
)
