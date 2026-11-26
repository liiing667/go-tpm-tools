package binding

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// MachineIdentityFromPublicKey creates a machine identity from the public key
// that signed an attestation quote. cert, when non-nil, additionally binds the
// GCE/TPM Attestation Key certificate to the identity.
func MachineIdentityFromPublicKey(pub crypto.PublicKey, cert *x509.Certificate) (MachineIdentity, error) {
	if pub == nil && cert != nil {
		pub = cert.PublicKey
	}
	if pub == nil {
		return MachineIdentity{}, fmt.Errorf("%w: no public key", ErrEmptyMachineIdentity)
	}
	// Some callers place a value rather than a pointer in crypto.PublicKey.
	switch k := pub.(type) {
	case ecdsa.PublicKey:
		pub = &k
	case rsa.PublicKey:
		pub = &k
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return MachineIdentity{}, fmt.Errorf("binding: marshal machine public key: %w", err)
	}
	id := MachineIdentity{AKPublicKeyDER: der}
	if cert != nil {
		id.AKCertificateDER = cert.Raw
	}
	if err := id.Validate(); err != nil {
		return MachineIdentity{}, err
	}
	return id, nil
}

// WithInstance returns a copy of the identity with instance metadata attached.
// It does not treat metadata alone as proof; the key/certificate remains the
// cryptographic component of the identity.
func (m MachineIdentity) WithInstance(instance *InstanceIdentity) MachineIdentity {
	m.Instance = instance
	return m
}

// WithID returns a copy with an explicit canonical machine resource ID.
func (m MachineIdentity) WithID(id string) MachineIdentity {
	m.ID = id
	return m
}
