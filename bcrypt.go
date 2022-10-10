package password

import (
	"context"
	"crypto/sha512"
	"fmt"
	"github.com/patrickmn/go-hmaccrypt"
	_ "log"
	"net/url"
)

type BCryptPassword struct {
	Password
	crypt  *hmaccrypt.HmacCrypt
	digest string
	salt   string
}

func init() {
	ctx := context.Background()
	RegisterPassword(ctx, "bcrypt", NewBCryptPassword)
}

func NewBCryptPassword(ctx context.Context, uri string) (Password, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, fmt.Errorf("Failed to parse URI, %w", err)
	}

	pswd := u.Host

	var salt string

	q := u.Query()

	if q.Get("salt") != "" {
		salt = q.Get("salt")
	} else {

		s, err := NewSalt()

		if err != nil {
			return nil, fmt.Errorf("Failed to create new salt, %w", err)
		}

		salt = s
	}

	digest := q.Get("digest")

	if digest != "" {
		return NewBCryptPasswordFromDigest(digest, salt)
	}

	return NewBCryptPasswordWithSalt(pswd, salt)
}

func NewBCryptPasswordFromDigest(digest string, salt string) (Password, error) {

	pepper := []byte(salt)
	crypt := hmaccrypt.New(sha512.New, pepper)

	p := BCryptPassword{
		digest: digest,
		crypt:  crypt,
		salt:   salt,
	}

	return &p, nil
}

func NewBCryptPasswordWithSalt(pswd string, salt string) (Password, error) {

	pepper := []byte(salt)
	crypt := hmaccrypt.New(sha512.New, pepper)

	b_pswd := []byte(pswd)
	digest, err := crypt.Bcrypt(b_pswd, 10)

	if err != nil {
		return nil, err
	}

	p := BCryptPassword{
		digest: string(digest),
		crypt:  crypt,
		salt:   salt,
	}

	return &p, nil
}

func (p *BCryptPassword) Digest() string {
	return p.digest
}

func (p *BCryptPassword) Salt() string {
	return p.salt
}

func (p *BCryptPassword) Compare(pswd string) error {
	return p.crypt.BcryptCompare([]byte(p.digest), []byte(pswd))
}
