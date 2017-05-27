package webidrsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	rnd "math/rand"
	"strconv"
	"time"
)

const (
	randLength  = 24
	randBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	randIdxBits = 6                  // 6 bits to represent a letter index
	randIdxMask = 1<<randIdxBits - 1 // All 1-bits, as many as letterIdxBits
	randIdxMax  = 63 / randIdxBits   // # of letter indices fitting in 63 bits
	rsaBits     = 2048
)

var randSrc = rnd.NewSource(time.Now().UnixNano())

// Signer creates signatures that verify against a public key.
type Signer interface {
	Sign(data []byte) ([]byte, error)
}

// Verifier verifies signatures against a public key.
type Verifier interface {
	Verify(data []byte, sig []byte) error
}

type rsaPubKey struct {
	*rsa.PublicKey
}

type rsaPrivKey struct {
	*rsa.PrivateKey
}

func NewRandomID() string {
	// id
	id := make([]byte, randLength)

	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := randLength-1, randSrc.Int63(), randIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSrc.Int63(), randIdxMax
		}
		if idx := int(cache & randIdxMask); idx < len(randBytes) {
			id[i] = randBytes[idx]
			i--
		}
		cache >>= randIdxBits
		remain--
	}

	return string(id)
}

// ParsePublicKeyNE parses a modulus and exponent and returns a new verifier object
func ParsePublicKeyNE(keyT, keyN, keyE string) (Verifier, error) {
	if len(keyN) == 0 || len(keyE) == 0 {
		return nil, errors.New("No modulus and/or exponent provided")
	}
	intN := new(big.Int)
	intN.SetString(keyN, 16)

	intE, err := strconv.ParseInt(keyE, 10, 0)
	if err != nil {
		return nil, err
	}

	var rawkey interface{}
	switch keyT {
	case "RSAPublicKey":
		rawkey = &rsa.PublicKey{
			N: intN,
			E: int(intE),
		}
	default:
		return nil, fmt.Errorf("Unsupported key type %q", keyT)
	}
	return newVerifierFromKey(rawkey)
}

// ParsePublicKey parses an RSA public key and returns a new verifier object
func ParsePublicKey(key *rsa.PublicKey) (Verifier, error) {
	return newVerifierFromKey(key)
}

// ParsePrivateKey parses an RSA private key and returns a new signer object
func ParsePrivateKey(key *rsa.PrivateKey) (Signer, error) {
	return newSignerFromKey(key)
}

// ParsePublicPEMKey parses a PEM encoded private key and returns a new verifier object
func ParsePublicPEMKey(pemBytes []byte) (Verifier, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("No key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PUBLIC KEY", "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("Unsupported key type %q", block.Type)
	}

	return newVerifierFromKey(rawkey)
}

// ParsePrivatePEMKey parses a PEM encoded private key and returns a Signer.
func ParsePrivatePEMKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("No key found or could not decode PEM key")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY", "PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("Unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sKey = &rsaPrivKey{t}
	default:
		return nil, fmt.Errorf("Unsupported key type %T", k)
	}
	return sKey, nil
}

func newVerifierFromKey(k interface{}) (Verifier, error) {
	var vKey Verifier
	switch t := k.(type) {
	case *rsa.PublicKey:
		vKey = &rsaPubKey{t}
	default:
		return nil, fmt.Errorf("Unsupported key type %T", k)
	}
	return vKey, nil
}

// Sign signs data with rsa-sha256
func (r *rsaPrivKey) Sign(data []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA1, data)
}

// Verify verifies the message using a rsa-sha256 signature
func (r *rsaPubKey) Verify(message []byte, sig []byte) error {
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA1, message, sig)
}
