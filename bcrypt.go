package password

import (
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"unicode/utf8"

	"github.com/patrickmn/go-hmaccrypt"
	"golang.org/x/crypto/bcrypt"
)

// DefaultBCryptCost is the bcrypt work factor used when no "cost" parameter is given.
const DefaultBCryptCost = 12

// MaxBCryptCost is the highest bcrypt cost accepted, whether for new hashes or digests that
// are loaded, to stop an untrusted digest from forcing excessive CPU use in Compare.
const MaxBCryptCost = 16

// BCryptPassword is a Password that stores bcrypt(HMAC-SHA512(password, key)) digests. The
// HMAC pre-hash avoids bcrypt's 72 byte input limit.
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
//	bcrypt:///?digest=DIGEST&salt=SALT[&pepper=SECRET]
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

	u, err := parseURI(uri)

	if err != nil {
		return nil, err
	}

	q := u.Query()

	pswd, err := plaintextFromURL(u, "digest", "salt", "pepper", "cost")

	if err != nil {
		return nil, err
	}

	digest := q.Get("digest")
	salt := q.Get("salt")
	pepper := q.Get("pepper")

	cost := DefaultBCryptCost

	if q.Get("cost") != "" {

		cost, err = strconv.Atoi(q.Get("cost"))

		if err != nil {
			return nil, fmt.Errorf("Invalid bcrypt cost, %w", err)
		}
	}

	if salt == "" {

		// A new salt can not verify an existing digest.
		if digest != "" && pepper == "" {
			return nil, errors.New("A digest requires the salt (or pepper) it was created with")
		}

		s, err := NewSalt()

		if err != nil {
			return nil, fmt.Errorf("Failed to create new salt, %w", err)
		}

		salt = s
	}

	return newBCryptPassword(pswd, digest, salt, pepper, cost)
}

// NewBCryptPasswordFromDigest returns a Password for an existing bcrypt 'digest' that was
// created using 'salt' as its HMAC key.
func NewBCryptPasswordFromDigest(digest string, salt string) (Password, error) {

	if digest == "" || salt == "" {
		return nil, errors.New("A digest and its salt are required")
	}

	return newBCryptPassword("", digest, salt, "", DefaultBCryptCost)
}

// NewBCryptPasswordWithSalt returns a new Password for the plain text 'pswd' using 'salt' as its HMAC key.
func NewBCryptPasswordWithSalt(pswd string, salt string) (Password, error) {

	if salt == "" {
		return nil, errors.New("A salt is required")
	}

	return newBCryptPassword(pswd, "", salt, "", DefaultBCryptCost)
}

func newBCryptPassword(pswd string, digest string, salt string, pepper string, cost int) (Password, error) {

	key := pepper

	if key == "" {
		key = salt
	}

	crypt := hmaccrypt.New(sha512.New, []byte(key))

	if digest == "" {

		if cost < bcrypt.MinCost || cost > MaxBCryptCost {
			return nil, errors.New("Invalid bcrypt cost")
		}

		if utf8.RuneCountInString(pswd) < MinPasswordLength {
			return nil, errPasswordTooShort()
		}

		d, err := crypt.Bcrypt([]byte(pswd), cost)

		if err != nil {
			return nil, fmt.Errorf("Failed to create digest, %w", err)
		}

		digest = string(d)

	} else {

		c, err := bcrypt.Cost([]byte(digest))

		if err != nil {
			return nil, fmt.Errorf("Invalid bcrypt digest, %w", err)
		}

		if c < bcrypt.MinCost || c > MaxBCryptCost {
			return nil, errors.New("Invalid bcrypt cost in digest")
		}
	}

	p := BCryptPassword{
		digest: digest,
		crypt:  crypt,
		salt:   salt,
	}

	return &p, nil
}

// Digest returns the bcrypt digest.
func (p *BCryptPassword) Digest() string {
	return p.digest
}

// Salt returns the salt used as (or alongside) the HMAC key. It is not a secret.
func (p *BCryptPassword) Salt() string {
	return p.salt
}

// Compare returns nil if 'pswd' matches the digest and an error otherwise.
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
