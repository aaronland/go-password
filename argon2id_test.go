package password

import (
	"context"
	"fmt"
	"net/url"
	"testing"
)

func TestArgon2idPassword(t *testing.T) {

	ctx := context.Background()
	uri := "argon2id://s33kret"

	p, err := NewPassword(ctx, uri)

	if err != nil {
		t.Fatalf("Failed to create new password, %v", err)
	}

	err = p.Compare("s33kret")

	if err != nil {
		t.Fatalf("Passwords do not compare, %v", err)
	}
}

func TestArgon2idPasswordFromDigest(t *testing.T) {

	ctx := context.Background()
	uri := "argon2id://s33kret"

	p, err := NewPassword(ctx, uri)

	if err != nil {
		t.Fatalf("Failed to create new password, %v", err)
	}

	err = p.Compare("s33kret")

	if err != nil {
		t.Fatalf("Passwords do not compare, %v", err)
	}

	hash_uri := fmt.Sprintf("argon2id://?hash=%s", url.QueryEscape(p.Digest()))

	p2, err := NewPassword(ctx, hash_uri)

	if err != nil {
		t.Fatalf("Failed to create password from hash URI, %v", err)
	}

	err = p2.Compare("s33kret")

	if err != nil {
		t.Fatalf("Passwords (p2) do not compare, %v", err)
	}

}
