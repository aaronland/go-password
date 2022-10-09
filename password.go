package password

import (
	"context"
	"fmt"
	"github.com/aaronland/go-roster"
	"net/url"
	"sort"
	"strings"
)

type Password interface {
	Digest() string
	Salt() string
	Compare(string) error
}

var password_roster roster.Roster

// PasswordInitializationFunc is a function defined by individual password package and used to create
// an instance of that password
type PasswordInitializationFunc func(ctx context.Context, uri string) (Password, error)

// RegisterPassword registers 'scheme' as a key pointing to 'init_func' in an internal lookup table
// used to create new `Password` instances by the `NewPassword` method.
func RegisterPassword(ctx context.Context, scheme string, init_func PasswordInitializationFunc) error {

	err := ensurePasswordRoster()

	if err != nil {
		return err
	}

	return password_roster.Register(ctx, scheme, init_func)
}

func ensurePasswordRoster() error {

	if password_roster == nil {

		r, err := roster.NewDefaultRoster()

		if err != nil {
			return err
		}

		password_roster = r
	}

	return nil
}

// NewPassword returns a new `Password` instance configured by 'uri'. The value of 'uri' is parsed
// as a `url.URL` and its scheme is used as the key for a corresponding `PasswordInitializationFunc`
// function used to instantiate the new `Password`. It is assumed that the scheme (and initialization
// function) have been registered by the `RegisterPassword` method.
func NewPassword(ctx context.Context, uri string) (Password, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	scheme := u.Scheme

	i, err := password_roster.Driver(ctx, scheme)

	if err != nil {
		return nil, err
	}

	init_func := i.(PasswordInitializationFunc)
	return init_func(ctx, uri)
}

// Schemes returns the list of schemes that have been registered.
func Schemes() []string {

	ctx := context.Background()
	schemes := []string{}

	err := ensurePasswordRoster()

	if err != nil {
		return schemes
	}

	for _, dr := range password_roster.Drivers(ctx) {
		scheme := fmt.Sprintf("%s://", strings.ToLower(dr))
		schemes = append(schemes, scheme)
	}

	sort.Strings(schemes)
	return schemes
}
