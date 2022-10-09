package x25519

import (
	"encoding/base64"

	"github.com/xiaoyang-chen/x25519/internal/age"

	"github.com/pkg/errors"
)

type ageX25519Wrap struct{}
type AgeX25519 interface {
	GeneratePubKeyAndPrivateKey(pubPrefix, privatePrefix string) (pub, private string, err error)
	EncryptByPubKeyWithPrefix(in []byte, publicKey, prefix string) (out []byte, err error)
	DecryptByPrivateKeyWithPrefix(in []byte, privateKey, prefix string) (out []byte, err error)
	// EncryptByPubKeyWithPrefixBeforeBase64 encrypt and then base64 encode, if encoding is nil, it will use base64.RawStdEncoding, this method is usually used to handle messy code
	EncryptByPubKeyWithPrefixBeforeBase64(in []byte, publicKey, prefix string, encoding *base64.Encoding) (out []byte, err error)
	// DecryptByPrivateKeyWithPrefixAfterBase64 base64 decode and then decrypt, if encoding is nil, it will use base64.RawStdEncoding, this method is usually used to handle messy code
	DecryptByPrivateKeyWithPrefixAfterBase64(in []byte, privateKey, prefix string, encoding *base64.Encoding) (out []byte, err error)
}

func NewAgeX25519() AgeX25519 { return new(ageX25519Wrap) }

func (*ageX25519Wrap) GeneratePubKeyAndPrivateKey(pubPrefix, privatePrefix string) (pub, private string, err error) {

	var x25519Identity *age.X25519Identity
	if x25519Identity, err = age.GenerateX25519Identity(); err != nil {
		err = errors.Wrap(err, "generate x25519 identity fail")
		return
	}
	if pub, err = x25519Identity.PublicKey(pubPrefix); err != nil {
		err = errors.WithMessage(err, "generate x25519 public key fail")
		return
	}
	if private, err = x25519Identity.PrivateKey(privatePrefix); err != nil {
		err = errors.WithMessage(err, "generate x25519 private key fail")
	}
	return
}

func (*ageX25519Wrap) EncryptByPubKeyWithPrefix(in []byte, publicKey, prefix string) (out []byte, err error) {

	out, err = age.EncryptByX25519PublicKey(in, publicKey, prefix)
	return
}

func (*ageX25519Wrap) DecryptByPrivateKeyWithPrefix(in []byte, privateKey, prefix string) (out []byte, err error) {

	out, err = age.DecryptByX25519PrivateKey(in, privateKey, prefix)
	return
}

func (*ageX25519Wrap) EncryptByPubKeyWithPrefixBeforeBase64(in []byte, publicKey, prefix string, encoding *base64.Encoding) (out []byte, err error) {

	if out, err = age.EncryptByX25519PublicKey(in, publicKey, prefix); err == nil {
		if encoding == nil {
			encoding = base64.RawStdEncoding
		}
		var base64Out = make([]byte, encoding.EncodedLen(len(out)))
		encoding.Encode(base64Out, out)
		out = base64Out
	}
	return
}

func (*ageX25519Wrap) DecryptByPrivateKeyWithPrefixAfterBase64(in []byte, privateKey, prefix string, encoding *base64.Encoding) (out []byte, err error) {

	if encoding == nil {
		encoding = base64.RawStdEncoding
	}
	var base64In = make([]byte, encoding.DecodedLen(len(in)))
	var n int
	if n, err = encoding.Decode(base64In, in); err != nil {
		err = errors.Wrap(err, "base64 decode fail")
		return
	}
	out, err = age.DecryptByX25519PrivateKey(base64In[:n], privateKey, prefix)
	return
}
