package password

import (
	"crypto/rand"
	"encoding/base64"
)

// NewSalt returns 32 bytes from crypto/rand, encoded as URL-safe base64
// so that it can be embedded in a URI without escaping.
func NewSalt() (string, error) {

	b := make([]byte, 32)

	_, err := rand.Read(b)

	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
