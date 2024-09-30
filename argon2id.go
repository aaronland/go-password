package password

// https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go
// https://github.com/alexedwards/argon2id

import (
	"context"
	"fmt"
	"net/url"
	"regexp"

	"github.com/alexedwards/argon2id"
)

var re_hash = regexp.MustCompile(`^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(.*)$`)

type Argon2idPassword struct {
	Password
	hash string
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

	var hash string

	if u.Host != "" {

		pswd := u.Host

		params := argon2id.DefaultParams

		// To do: Allow custom params here...

		h, err := argon2id.CreateHash(pswd, params)

		if err != nil {
			return nil, fmt.Errorf("Failed to create hash, %w", err)
		}

		hash = h

	} else {

		q := u.Query()

		q_hash := q.Get("hash")

		if q_hash == "" {
			return nil, fmt.Errorf("Missing ?hash= parameter, %w", err)
		}

		_, _, _, err := argon2id.DecodeHash(q_hash)

		if err != nil {
			return nil, fmt.Errorf("Failed to decode ?hash= parameter, %w", err)
		}

		hash = q_hash
	}

	p := &Argon2idPassword{
		hash: hash,
	}

	return p, nil
}

func (p *Argon2idPassword) Digest() string {
	return p.hash
}

func (p *Argon2idPassword) Salt() string {
	// To do: This can be derived using re_hash (above)
	return ""
}

func (p *Argon2idPassword) Compare(pswd string) error {

	ok, err := argon2id.ComparePasswordAndHash(pswd, p.hash)

	if err != nil {
		return fmt.Errorf("Failed to compare hash, %w", err)
	}

	if !ok {
		return fmt.Errorf("Invalid match")
	}

	return nil
}
