package roster

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Factory is a function that creates a new instance of T from a URI.
type Factory[T any] func(ctx context.Context, uri string) (T, error)

// Registry is a type-safe lookup table mapping URI schemes to `Factory[T]` functions.
// Schemes are case-insensitive. It is safe for concurrent use.
type Registry[T any] struct {
	mu        sync.RWMutex
	factories map[string]Factory[T]
}

// NewRegistry returns a new, empty `Registry` for creating values of type T.
func NewRegistry[T any]() *Registry[T] {
	return &Registry[T]{
		factories: make(map[string]Factory[T]),
	}
}

func normalize(scheme string) string {
	return strings.ToUpper(scheme)
}

// Register associates 'scheme' with 'f'. It returns an error if 'f' is nil or 'scheme' is already registered.
func (r *Registry[T]) Register(ctx context.Context, scheme string, f Factory[T]) error {

	if f == nil {
		return fmt.Errorf("Nothing to register for scheme '%s'", scheme)
	}

	key := normalize(scheme)

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, dup := r.factories[key]; dup {
		return fmt.Errorf("Register called twice for '%s'", scheme)
	}

	r.factories[key] = f
	return nil
}

// MustRegister is like `Register` but panics if registration fails. It is intended for use in `init` functions.
func (r *Registry[T]) MustRegister(ctx context.Context, scheme string, f Factory[T]) {

	if err := r.Register(ctx, scheme, f); err != nil {
		panic(fmt.Sprintf("Failed to register '%s': %v", scheme, err))
	}
}

// New parses 'uri' and invokes the `Factory` registered for its scheme.
func (r *Registry[T]) New(ctx context.Context, uri string) (T, error) {

	var zero T

	u, err := url.Parse(uri)

	if err != nil {
		return zero, fmt.Errorf("Failed to parse URI, %w", err)
	}

	r.mu.RLock()
	f, ok := r.factories[normalize(u.Scheme)]
	r.mu.RUnlock()

	if !ok {
		return zero, fmt.Errorf("Unknown scheme: '%s'", u.Scheme)
	}

	return f(ctx, uri)
}

// Schemes returns the sorted list of registered schemes, each formatted as "scheme://".
func (r *Registry[T]) Schemes(ctx context.Context) []string {

	r.mu.RLock()
	defer r.mu.RUnlock()

	schemes := make([]string, 0, len(r.factories))

	for key := range r.factories {
		schemes = append(schemes, strings.ToLower(key)+"://")
	}

	sort.Strings(schemes)
	return schemes
}
