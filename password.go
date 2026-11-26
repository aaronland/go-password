package password

import (
	"context"
	"github.com/aaronland/go-roster/v2"
)

type Password interface {
	Digest() string
	Salt() string
	Compare(string) error
	String() string
}

type PasswordInitializationFunc = roster.Factory[Password]

var password_registry = roster.NewRegistry[Password]()

// NewService creates a Password from a URI whose scheme selects a registered implementation.
func NewService(ctx context.Context, uri string) (Password, error) {
	return password_registry.New(ctx, uri)
}

func RegisterPassword(ctx context.Context, scheme string, init_func PasswordInitializationFunc) error {
	return password_registry.Register(ctx, scheme, init_func)
}

// NewPassword is equivalent to NewService.
func NewPassword(ctx context.Context, uri string) (Password, error) {
	return NewService(ctx, uri)
}

// Passwords returns the registered schemes, formatted as "scheme://".
func Passwords() []string {
	return password_registry.Schemes(context.Background())
}
