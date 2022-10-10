package password

import (
	"context"
	"fmt"
	"testing"
)

func TestBcryptPassword(t *testing.T) {

	ctx := context.Background()
	uri := "bcrypt://s33kret"

	p, err := NewPassword(ctx, uri)

	if err != nil {
		t.Fatalf("Failed to create new password, %v", err)
	}

	err = p.Compare("s33kret")

	if err != nil {
		t.Fatalf("Passwords do not compare, %v", err)
	}
}

func TestBcryptPasswordFromDigest(t *testing.T) {

	ctx := context.Background()
	uri := "bcrypt://s33kret"

	p, err := NewPassword(ctx, uri)

	if err != nil {
		t.Fatalf("Failed to create new password, %v", err)
	}

	err = p.Compare("s33kret")

	if err != nil {
		t.Fatalf("Passwords do not compare, %v", err)
	}

	digest_uri := fmt.Sprintf("bcrypt://?digest=%s&salt=%s", p.Digest(), p.Salt())

	p2, err := NewPassword(ctx, digest_uri)

	if err != nil {
		t.Fatalf("Failed to create password from digest, %v", err)
	}

	err = p2.Compare("s33kret")

	if err != nil {
		t.Fatalf("Passwords (p2) do not compare, %v", err)
	}

}
