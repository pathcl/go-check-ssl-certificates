package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net"
	"time"
)

type Cert struct {
	CommonName       string    `json:"cn"`
	NotAfter         time.Time `json:"expires"`
	IssuerCommonName string    `json:"issuer"`
}

func getVerifiedCertificateChains(addr string, timeoutSecond time.Duration) ([][]*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeoutSecond * time.Second}, "tcp", addr, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	chains := conn.ConnectionState().VerifiedChains
	return chains, nil
}

func ParseRemoteCertificate(addr string, timeoutSecond int) (*Cert, error) {
	chains, err := getVerifiedCertificateChains(addr, time.Duration(timeoutSecond))
	if err != nil {
		return nil, err
	}

	var cert *Cert
	for _, chain := range chains {
		for _, crt := range chain {
			if !crt.IsCA {
				cert = &Cert{
					CommonName:       crt.Subject.CommonName,
					NotAfter:         crt.NotAfter,
					IssuerCommonName: crt.Issuer.CommonName,
				}
			}
		}
	}
	return cert, err
}

func ParseCertificateFile(certFile string) (*Cert, error) {
	b, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	crt, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, err
	}
	return &Cert{
		CommonName:       crt.Subject.CommonName,
		NotAfter:         crt.NotAfter,
		IssuerCommonName: crt.Issuer.CommonName,
	}, err
}

func (cert *Cert) Jsonify() string {
	b, _ := json.Marshal(cert)
	return string(b)
}
