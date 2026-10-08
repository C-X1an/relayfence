package relayfence

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/url"
	"time"
)

func (p *labPKI) expiredClient() (tls.Certificate, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return tls.Certificate{}, e
	}
	u, _ := url.Parse(labIdentity)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1000), NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}
	der, e := x509.CreateCertificate(rand.Reader, tpl, p.ca, &key.PublicKey, p.key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, e
}
