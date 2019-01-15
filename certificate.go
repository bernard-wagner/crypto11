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
	"crypto/x509"

	"github.com/miekg/pkcs11"
)

// FindCertificate retrieves a previously imported certificate
//
// Either (but not all three) of id, label and serial may be nil, in which case they are ignored.
func FindCertificate(id []byte, label []byte, serial []byte) (*x509.Certificate, error) {
	return FindCertificateOnSlot(instance.slot, id, label, serial)
}

// FindCertificateOnSlot retrieves previously imported certificate on a specified slot
//
// Either (but not all three) of id, label and serial may be nil, in which case they are ignored.
func FindCertificateOnSlot(slot uint, id []byte, label []byte, serial []byte) (*x509.Certificate, error) {
	var err error
	var c *x509.Certificate
	if err = ensureSessions(instance, slot); err != nil {
		return nil, err
	}
	err = withSession(slot, func(session *PKCS11Session) error {
		c, err = FindCertificateOnSession(session, slot, id, label, serial)
		return err
	})
	return c, err
}

// FindCertificateOnSession retrieves a previously imported certificate.
//
// Either (but not all three) of id, label and serial may be nil, in which case they are ignored.
func FindCertificateOnSession(session *PKCS11Session, slot uint, id []byte, label []byte, serial []byte) (*x509.Certificate, error) {
	var err error
	var handles []pkcs11.ObjectHandle
	var template []*pkcs11.Attribute

	template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE))
	template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509))
	if id != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if label != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}
	if serial != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, serial))
	}
	if err = session.Ctx.FindObjectsInit(session.Handle, template); err != nil {
		return nil, err
	}
	defer session.Ctx.FindObjectsFinal(session.Handle)
	if handles, _, err = session.Ctx.FindObjects(session.Handle, 1); err != nil {
		return nil, err
	}
	if len(handles) == 0 {
		return nil, ErrCertificateNotFound
	}

	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, 0),
	}

	if attributes, err = session.Ctx.GetAttributeValue(session.Handle, handles[0], attributes); err != nil {
		return nil, err
	}

	return x509.ParseCertificate(attributes[0].Value)
}

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
	var err error
	if label == nil {
		if label, err = generateKeyLabel(); err != nil {
			return err
		}
	}
	if id == nil {
		if id, err = generateKeyLabel(); err != nil {
			return err
		}
	}

	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, certificate.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, certificate.RawIssuer),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, certificate.SerialNumber.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, certificate.Raw),
	}

	_, err = session.Ctx.CreateObject(session.Handle, attributes)

	return err
}
