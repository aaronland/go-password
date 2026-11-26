package password

import (
	"context"
	"net/url"
	"testing"
)

func TestArgon2idPassword(t *testing.T) {

	ctx := context.Background()
	uri := "argon2id://s33kret99"

	p, err := NewPassword(ctx, uri)

	if err != nil {
		t.Fatalf("Failed to create new password, %v", err)
	}

	err = p.Compare("s33kret99")

	if err != nil {
		t.Fatalf("Passwords do not compare, %v", err)
	}

	if p.Compare("s33kret98") == nil {
		t.Fatal("Wrong password matched")
	}
}

func TestArgon2idPasswordFromDigest(t *testing.T) {

	ctx := context.Background()

	p, err := NewPassword(ctx, "argon2id://s33kret99")

	if err != nil {
		t.Fatalf("Failed to create new password, %v", err)
	}

	hash_uri := "argon2id://?hash=" + url.QueryEscape(p.Digest())

	p2, err := NewPassword(ctx, hash_uri)

	if err != nil {
		t.Fatalf("Failed to create password from hash URI, %v", err)
	}

	err = p2.Compare("s33kret99")

	if err != nil {
		t.Fatalf("Passwords (p2) do not compare, %v", err)
	}

	// String() must round trip without panicking or leaking the plain text.
	p3, err := NewPassword(ctx, p.String())

	if err != nil {
		t.Fatalf("Failed to create password from String(), %v", err)
	}

	if err := p3.Compare("s33kret99"); err != nil {
		t.Fatalf("Passwords (p3) do not compare, %v", err)
	}
}

func TestArgon2idInvalid(t *testing.T) {

	ctx := context.Background()

	for _, uri := range []string{
		"argon2id://abcd/efghijkl", // would be truncated
		"argon2id://short",         // too short
		"argon2id://",              // nothing to hash
		"argon2id:///?hash=nope",   // undecodable hash
	} {
		if _, err := NewPassword(ctx, uri); err == nil {
			t.Fatalf("Expected error for %s", uri)
		}
	}
}
