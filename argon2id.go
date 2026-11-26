package password

// https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go
// https://github.com/alexedwards/argon2id

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"unicode/utf8"

	"github.com/alexedwards/argon2id"
)

// Upper bounds for the parameters of an argon2id hash that is loaded, so that an untrusted
// hash can not force Compare to use excessive memory or CPU.
const (
	MaxArgon2idMemory      = 256 * 1024 // KiB
	MaxArgon2idIterations  = 10
	MaxArgon2idParallelism = 16
)

func validateArgon2idHash(hash string) error {

	params, salt, key, err := argon2id.DecodeHash(hash)

	if err != nil {
		return fmt.Errorf("Failed to decode ?hash= parameter, %w", err)
	}

	if params.Memory == 0 || params.Memory > MaxArgon2idMemory ||
		params.Iterations == 0 || params.Iterations > MaxArgon2idIterations ||
		params.Parallelism == 0 || params.Parallelism > MaxArgon2idParallelism ||
		len(salt) == 0 || len(key) == 0 {
		return errors.New("Argon2id hash has invalid or excessive parameters")
	}

	return nil
}

// Argon2idPassword is a Password backed by an encoded argon2id hash (which includes its own salt
// and parameters).
type Argon2idPassword struct {
	hash string
}

func init() {

	ctx := context.Background()
	err := RegisterPassword(ctx, "argon2id", NewArgon2idPassword)

	if err != nil {
		panic(err)
	}
}

// NewArgon2idPassword creates a Password from a URI of the form:
//
//	argon2id:///?password=PLAINTEXT
//	argon2id:///?hash=HASH
//
// As with bcrypt the plain text may also be given as the URI host (argon2id://PLAINTEXT)
// if it contains no URI-significant characters.
func NewArgon2idPassword(ctx context.Context, uri string) (Password, error) {

	u, err := parseURI(uri)

	if err != nil {
		return nil, err
	}

	q := u.Query()

	q_hash := q.Get("hash")

	var hash string

	if q_hash != "" {

		if err := validateArgon2idHash(q_hash); err != nil {
			return nil, err
		}

		hash = q_hash

	} else {

		pswd, err := plaintextFromURL(u, "hash")

		if err != nil {
			return nil, err
		}

		if pswd == "" {
			return nil, errors.New("Missing password or ?hash= parameter")
		}

		if utf8.RuneCountInString(pswd) < MinPasswordLength {
			return nil, errPasswordTooShort()
		}

		// To do: Allow custom params here...
		h, err := argon2id.CreateHash(pswd, argon2id.DefaultParams)

		if err != nil {
			return nil, fmt.Errorf("Failed to create hash, %w", err)
		}

		hash = h
	}

	p := &Argon2idPassword{
		hash: hash,
	}

	return p, nil
}

// Digest returns the encoded argon2id hash.
func (p *Argon2idPassword) Digest() string {
	return p.hash
}

// Salt returns an empty string; the salt is encoded in the hash returned by Digest.
func (p *Argon2idPassword) Salt() string {
	return ""
}

// Compare returns nil if 'pswd' matches the hash and an error otherwise.
func (p *Argon2idPassword) Compare(pswd string) error {

	ok, err := argon2id.ComparePasswordAndHash(pswd, p.hash)

	if err != nil {
		return fmt.Errorf("Failed to compare hash, %w", err)
	}

	if !ok {
		return errors.New("Invalid match")
	}

	return nil
}

// String returns a URI containing the (URL-escaped) hash, never the plain text.
func (p *Argon2idPassword) String() string {

	q := url.Values{}
	q.Set("hash", p.hash)

	return "argon2id:///?" + q.Encode()
}
