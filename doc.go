// Package password provides a common interface for hashing and comparing passwords using
// different schemes, each selected by the scheme of a URI.
//
// Implementations register themselves with RegisterPassword (the "bcrypt" and "argon2id"
// schemes are registered by this package) and instances are created with NewPassword:
//
//	p, err := password.NewPassword(ctx, "bcrypt:///?password="+url.QueryEscape(plaintext))
//	...
//	err = p.Compare(plaintext)
//
// A Password can be serialized with its String method and later restored by passing the
// result back to NewPassword. The serialized form contains the hash (and, for bcrypt, the
// salt) but never the plain text. It should still be treated as sensitive.
//
// Randomness for salts and generated passwords is drawn from crypto/rand.
package password
