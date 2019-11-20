package identities

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"time"
)

type Template struct {
	AuthorityKeyID              []byte
	BasicConstraintsValid       bool
	CRLDistributionPoints       []string
	DNSNames                    []string
	EmailAddresses              []string
	ExcludedDNSDomains          []string
	ExcludedEmailAddresses      []string
	ExcludedIPRanges            []*net.IPNet
	ExcludedURIDomains          []string
	ExtKeyUsage                 []x509.ExtKeyUsage
	ExtraExtensions             []pkix.Extension
	IsCA                        bool
	IssuingCertificateURL       []string
	KeyUsage                    x509.KeyUsage
	MaxPathLen                  int
	MaxPathLenZero              bool
	NotAfter                    time.Time
	NotBefore                   time.Time
	OCSPServer                  []string
	PermittedDNSDomains         []string
	PermittedDNSDomainsCritical bool
	PermittedEmailAddresses     []string
	PermittedIPRanges           []*net.IPNet
	PermittedURIDomains         []string
	PolicyIdentifiers           []asn1.ObjectIdentifier
	SerialNumber                *big.Int
	SignatureAlgorithm          x509.SignatureAlgorithm
	Subject                     pkix.Name
	SubjectKeyID                []byte
	URIs                        []*url.URL
	UnknownExtKeyUsage          []asn1.ObjectIdentifier
}

func (t *Template) certificate() *x509.Certificate {
	return &x509.Certificate{
		AuthorityKeyId:              t.AuthorityKeyID,
		BasicConstraintsValid:       t.BasicConstraintsValid,
		CRLDistributionPoints:       t.CRLDistributionPoints,
		DNSNames:                    t.DNSNames,
		EmailAddresses:              t.EmailAddresses,
		ExcludedDNSDomains:          t.ExcludedDNSDomains,
		ExcludedEmailAddresses:      t.ExcludedEmailAddresses,
		ExcludedIPRanges:            t.ExcludedIPRanges,
		ExcludedURIDomains:          t.ExcludedURIDomains,
		ExtKeyUsage:                 t.ExtKeyUsage,
		ExtraExtensions:             t.ExtraExtensions,
		IsCA:                        t.IsCA,
		IssuingCertificateURL:       t.IssuingCertificateURL,
		KeyUsage:                    t.KeyUsage,
		MaxPathLen:                  t.MaxPathLen,
		MaxPathLenZero:              t.MaxPathLenZero,
		NotAfter:                    t.NotAfter,
		NotBefore:                   t.NotBefore,
		OCSPServer:                  t.OCSPServer,
		PermittedDNSDomains:         t.PermittedDNSDomains,
		PermittedDNSDomainsCritical: t.PermittedDNSDomainsCritical,
		PermittedEmailAddresses:     t.PermittedEmailAddresses,
		PermittedIPRanges:           t.PermittedIPRanges,
		PermittedURIDomains:         t.PermittedURIDomains,
		PolicyIdentifiers:           t.PolicyIdentifiers,
		SerialNumber:                t.SerialNumber,
		SignatureAlgorithm:          t.SignatureAlgorithm,
		Subject:                     t.Subject,
		SubjectKeyId:                t.SubjectKeyID,
		URIs:                        t.URIs,
		UnknownExtKeyUsage:          t.UnknownExtKeyUsage,
	}
}
