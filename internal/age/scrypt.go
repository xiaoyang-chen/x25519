// copy from https://github.com/FiloSottile/age/blob/v1.0.0/scrypt.go

// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package age

import (
	"crypto/rand"
	"fmt"
	"strconv"

	// "filippo.io/age/internal/format"
	"github.com/xiaoyang-chen/x25519/internal/age/internal/format"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

const scryptLabel = "age-encryption.org/v1/scrypt"

// ScryptRecipient is a password-based recipient. Anyone with the password can
// decrypt the message.
//
// If a ScryptRecipient is used, it must be the only recipient for the file: it
// can't be mixed with other recipient types and can't be used multiple times
// for the same file.
//
// Its use is not recommended for automated systems, which should prefer
// X25519Recipient.
type ScryptRecipient struct {
	password   []byte
	workFactor int
}

const scryptSaltSize = 16

func (r *ScryptRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	salt := make([]byte, scryptSaltSize)
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}

	logN := r.workFactor
	l := &Stanza{
		Type: "scrypt",
		Args: []string{format.EncodeToString(salt), strconv.Itoa(logN)},
	}

	salt = append([]byte(scryptLabel), salt...)
	k, err := scrypt.Key(r.password, salt, 1<<logN, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate scrypt hash: %v", err)
	}

	wrappedKey, err := aeadEncrypt(k, fileKey)
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey

	return []*Stanza{l}, nil
}
