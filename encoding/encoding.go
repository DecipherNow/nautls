package encoding

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func PEMEncodeCertificate(certificate *x509.Certificate) []byte {
	if certificate == nil {
		return []byte{}
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})
}

func PEMEncodeCertificates(certificates []*x509.Certificate) [][]byte {
	pems := make([][]byte, len(certificates))
	for i, cert := range certificates {
		pems[i] = PEMEncodeCertificate(cert)
	}
	return pems
}

func PEMEncodeKey(key *rsa.PrivateKey) []byte {
	if key == nil {
		return []byte{}
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func PEMEncodeKeys(keys []*rsa.PrivateKey) [][]byte {
	pems := make([][]byte, len(keys))
	for i, key := range keys {
		pems[i] = PEMEncodeKey(key)
	}
	return pems
}
