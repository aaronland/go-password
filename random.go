package password

import (
	"crypto/rand"
	"encoding/base32"
)

// NewRandomPassword returns a 32 character password (160 bits of entropy)
// generated with crypto/rand.
func NewRandomPassword() (string, error) {

	b := make([]byte, 20)

	_, err := rand.Read(b)

	if err != nil {
		return "", err
	}

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
