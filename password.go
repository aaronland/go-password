package password

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"

	"github.com/aaronland/go-roster/v2"
)

// MinPasswordLength is the minimum length (in characters) of a plain text password that will be hashed.
const MinPasswordLength = 8

// Password is the interface implemented by all password hashing schemes.
type Password interface {
	// Digest returns the hashed password.
	Digest() string
	// Salt returns the salt used to create the digest, or an empty string if the
	// salt is encoded in the digest itself.
	Salt() string
	// Compare returns nil if the plain text password matches the digest and an error otherwise.
	Compare(string) error
	// String returns a URI from which the Password can be recreated using NewPassword.
	// It never includes the plain text password.
	String() string
}

// PasswordInitializationFunc is a function defined by individual password package and used to create
// an instance of that password
type PasswordInitializationFunc = roster.Factory[Password]

var password_registry = roster.NewRegistry[Password]()

// RegisterPassword registers 'scheme' as a key pointing to 'init_func' in an internal lookup table
// used to create new `Password` instances by the `NewPassword` method.
func RegisterPassword(ctx context.Context, scheme string, init_func PasswordInitializationFunc) error {
	return password_registry.Register(ctx, scheme, init_func)
}

// NewPassword returns a new `Password` instance configured by 'uri'. The value of 'uri' is parsed
// as a `url.URL` and its scheme is used as the key for a corresponding `PasswordInitializationFunc`
// function used to instantiate the new `Password`. It is assumed that the scheme (and initialization
// function) have been registered by the `RegisterPassword` method.
func NewPassword(ctx context.Context, uri string) (Password, error) {

	// Parse here first so that a malformed URI (which may contain the plain text password)
	// is never echoed back in an error by the registry.
	if _, err := parseURI(uri); err != nil {
		return nil, err
	}

	return password_registry.New(ctx, uri)
}

// NewService is equivalent to NewPassword.
func NewService(ctx context.Context, uri string) (Password, error) {
	return NewPassword(ctx, uri)
}

// Schemes returns the sorted list of schemes that have been registered, formatted as "scheme://".
func Schemes() []string {
	return password_registry.Schemes(context.Background())
}

// Passwords is equivalent to Schemes.
//
// Deprecated: use Schemes.
func Passwords() []string {
	return Schemes()
}

// parseURI parses 'uri'. Unlike url.Parse, errors never include the URI because it may
// contain a plain text password or pepper.
func parseURI(uri string) (*url.URL, error) {

	u, err := url.Parse(uri)

	if err != nil {
		var url_err *url.Error

		if errors.As(err, &url_err) {
			return nil, fmt.Errorf("Failed to parse URI, %w", url_err.Err)
		}

		return nil, errors.New("Failed to parse URI")
	}

	// Query() silently drops malformed pairs, which could discard a password or pepper.
	// The error is deliberately generic as ParseQuery errors quote the offending text.
	if _, err := url.ParseQuery(u.RawQuery); err != nil {
		return nil, errors.New("Failed to parse URI, invalid query string")
	}

	return u, nil
}

// plaintextFromURL returns the plain text password in 'u'. It is read from the "password" query
// parameter or, failing that, the URL host. Host values that would have been truncated or
// reinterpreted by the URL parser (paths, userinfo, fragments, an opaque part or a query string
// containing anything other than the 'allowed' parameters) are rejected rather than silently
// shortened.
func plaintextFromURL(u *url.URL, allowed ...string) (string, error) {

	pswd := u.Query().Get("password")

	if pswd != "" {
		return pswd, nil
	}

	if u.User != nil || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || (u.Path != "" && u.Path != "/") {
		return "", errors.New("Password contains characters that are not valid in a URI host, use the 'password' query parameter")
	}

	for k := range u.Query() {

		if !slices.Contains(allowed, k) {
			return "", errors.New("Password contains characters that are not valid in a URI host, use the 'password' query parameter")
		}
	}

	return u.Host, nil
}

func errPasswordTooShort() error {
	return fmt.Errorf("Password too short (minimum %d characters)", MinPasswordLength)
}
