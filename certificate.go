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
