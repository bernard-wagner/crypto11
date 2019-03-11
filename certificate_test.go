// Copyright 2018 Thales e-Security, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package crypto11

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
)

// ImportCertificate imports a certificate on a specified slot and populates the available attributes
//
// The key will have a random label and ID.
func ImportCertificate(id []byte, label []byte, certificate *x509.Certificate) error {
	return ImportCertificateOnSlot(instance.slot, id, label, certificate)
}

// ImportCertificateOnSlot imports a certificate on a specified slot and populates the available attributes
//
// Either or both label and/or id can be nil, in which case random values will be generated.
func ImportCertificateOnSlot(slot uint, id []byte, label []byte, certificate *x509.Certificate) error {
	var err error
	if err = ensureSessions(instance, slot); err != nil {
		return err
	}
	err = withSession(slot, func(session *PKCS11Session) error {
		return ImportCertificateOnSession(session, slot, id, label, certificate)
	})
	return err
}

// ImportCertificateOnSession imports a certificate and populates the available attributes
//
// Either or both label and/or id can be nil, in which case random values will be generated.
func ImportCertificateOnSession(session *PKCS11Session, slot uint, id []byte, label []byte, certificate *x509.Certificate) error {
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, certificate.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, []byte(certificate.RawIssuer)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, certificate.SerialNumber.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, certificate.Raw),
	}

	_, err := session.Ctx.CreateObject(session.Handle, attributes)

	return err
}
func TestCertificate(t *testing.T) {
	var err error
	var key *PKCS11PrivateKeyRSA
	ConfigureFromFile("config")
	if key, err = GenerateRSAKeyPair(2048); err != nil {
		t.Errorf("GenerateRSAKeyPair: %v", err)
		return
	}

	if err = key.Validate(); err != nil {
		t.Errorf("crypto.rsa.PrivateKey.Validate: %v", err)
		return
	}
	notBefore := time.Now()
	notAfter := notBefore.AddDate(10, 0, 0)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Errorf("failed to generate serial number: %s", err)
		return
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := []string{"example.com"}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, key.PubKey, key)
	if err != nil {
		t.Errorf("Failed to create certificate: %s", err)
		return
	}

	cert, err := x509.ParseCertificate(derBytes)
	if cert == nil {
		t.Errorf("failed to parse certificate")
		return
	}

	if err := ImportCertificate(nil, []byte("test"), cert); err != nil {
		t.Errorf("ImportCertificate: %v", err)
	}

	cert2, err := FindCertificate(nil, []byte("test"), nil)

	if err != nil {
		t.Errorf("FindCertificate: %v", err)
		return
	}

	if !bytes.Equal(cert2.Signature, cert.Signature) {
		t.Errorf("invalid certificate")
		return
	}

	cert2, err = FindCertificate(nil, []byte("test2"), nil)

	if err == nil {
		t.Errorf("expected error if certificate does not exist")
		return
	}

	cert2, err = FindCertificate(nil, nil, cert.SerialNumber.Bytes())

	if err != nil {
		t.Errorf("FindCertificate: %v", err)
		return
	}

	if !bytes.Equal(cert2.Signature, cert.Signature) {
		t.Errorf("invalid certificate")
		return
	}

}
