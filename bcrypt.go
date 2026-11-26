package password

import (
	"context"
	"crypto/sha512"
	"errors"
	"github.com/patrickmn/go-hmaccrypt"
	"golang.org/x/crypto/bcrypt"
	"net/url"
	"strconv"
	"unicode/utf8"
)

// DefaultBCryptCost is the bcrypt work factor used when no "cost" parameter is given.
const DefaultBCryptCost = 12

const minPasswordLength = 8

type BCryptPassword struct {
	crypt  *hmaccrypt.HmacCrypt
	digest string
	salt   string
}

func init() {

	ctx := context.Background()
	err := RegisterPassword(ctx, "bcrypt", NewBCryptPassword)

	if err != nil {
		panic(err)
	}
}

// NewBCryptPassword creates a Password from a URI of the form:
//
//	bcrypt:///?password=PLAINTEXT[&salt=SALT][&pepper=SECRET][&cost=N]
//	bcrypt:///?digest=DIGEST&salt=SALT
//
// The plain text may also be given as the URI host (bcrypt://PLAINTEXT) but only
// if it contains no characters that are significant in a URI; values that would
// be truncated or reinterpreted are rejected. Use the (URL-escaped) "password"
// query parameter for arbitrary passwords.
//
// The HMAC key is the "pepper" parameter if present, otherwise the salt. The salt
// is serialized alongside the digest by String() so it is NOT a secret. To get any
// benefit from HMAC-ing, supply a secret "pepper" and store it separately from
// the digests; the pepper is never serialized and must be supplied again whenever
// a digest is loaded.
func NewBCryptPassword(ctx context.Context, uri string) (Password, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	q := u.Query()

	pswd := q.Get("password")

	if pswd == "" {

		if u.User != nil || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return nil, errors.New("Password contains characters that are not valid in a URI host, use the 'password' query parameter")
		}

		pswd = u.Host
	}

	digest := q.Get("digest")
	salt := q.Get("salt")
	pepper := q.Get("pepper")

	cost := DefaultBCryptCost

	if q.Get("cost") != "" {

		cost, err = strconv.Atoi(q.Get("cost"))

		if err != nil {
			return nil, err
		}

		if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
			return nil, errors.New("Invalid bcrypt cost")
		}
	}

	if salt == "" {

		// A new salt can not verify an existing digest.
		if digest != "" && pepper == "" {
			return nil, errors.New("A digest requires the salt (or pepper) it was created with")
		}

		s, err := NewSalt()

		if err != nil {
			return nil, err
		}

		salt = s
	}

	key := pepper

	if key == "" {
		key = salt
	}

	crypt := hmaccrypt.New(sha512.New, []byte(key))

	if digest == "" {

		if utf8.RuneCountInString(pswd) < minPasswordLength {
			return nil, errors.New("Password too short")
		}

		d, err := crypt.Bcrypt([]byte(pswd), cost)

		if err != nil {
			return nil, err
		}

		digest = string(d)
	}

	p := BCryptPassword{
		digest: digest,
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

// String returns a URI containing the digest and salt (never the pepper or plain text).
// Both values are URL-escaped so the result can be passed back to NewBCryptPassword.
// It contains the material needed to attack the hash offline so avoid logging it.
func (p *BCryptPassword) String() string {

	q := url.Values{}
	q.Set("digest", p.digest)
	q.Set("salt", p.salt)

	return "bcrypt:///?" + q.Encode()
}
