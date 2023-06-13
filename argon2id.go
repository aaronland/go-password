package password

// https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go
// https://github.com/alexedwards/argon2id

import (
	"context"
	"fmt"
	"net/url"

	"github.com/alexedwards/argon2id"
)

type Argon2idPassword struct {
	Password
	digest string
}

func init() {
	ctx := context.Background()
	RegisterPassword(ctx, "argon2id", NewArgon2idPassword)
}

func NewArgon2idPassword(ctx context.Context, uri string) (Password, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, fmt.Errorf("Failed to parse URI, %w", err)
	}

	var digest string

	if u.Host != "" {

		pswd := u.Host

		params := argon2id.DefaultParams

		// To do: Allow custom params here...

		d, err := argon2id.CreateHash(pswd, params)

		if err != nil {
			return nil, fmt.Errorf("Failed to create hash, %w", err)
		}

		digest = d

	} else {

		q := u.Query()

		q_digest := q.Get("digest")

		if q_digest == "" {
			return nil, fmt.Errorf("Missing ?digest= parameter, %w", err)
		}

		_, _, _, err := argon2id.DecodeHash(q_digest)

		if err != nil {
			return nil, fmt.Errorf("Failed to decode ?digest= parameter, %w", err)
		}

		digest = q_digest
	}

	p := &Argon2idPassword{
		digest: digest,
	}

	return p, nil
}

func (p *Argon2idPassword) Digest() string {
	return p.digest
}

func (p *Argon2idPassword) Salt() string {
	return ""
}

func (p *Argon2idPassword) Compare(pswd string) error {

	ok, err := argon2id.ComparePasswordAndHash(pswd, p.digest)

	if err != nil {
		return fmt.Errorf("Failed to compare hash, %w", err)
	}

	if !ok {
		return fmt.Errorf("Invalid match")
	}

	return nil
}
