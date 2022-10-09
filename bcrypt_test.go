package password

import (
	"context"
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
