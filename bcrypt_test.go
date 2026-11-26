package password

import (
	"context"
	"fmt"
	"net/url"
	"testing"
)

func TestBcryptPassword(t *testing.T) {

	ctx := context.Background()
	uri := "bcrypt://s33kret99"

	p, err := NewPassword(ctx, uri)

	if err != nil {
		t.Fatalf("Failed to create new password, %v", err)
	}

	err = p.Compare("s33kret99")

	if err != nil {
		t.Fatalf("Passwords do not compare, %v", err)
	}
}

func TestBcryptPasswordFromDigest(t *testing.T) {

	ctx := context.Background()
	uri := "bcrypt://s33kret99"

	p, err := NewPassword(ctx, uri)

	if err != nil {
		t.Fatalf("Failed to create new password, %v", err)
	}

	err = p.Compare("s33kret99")

	if err != nil {
		t.Fatalf("Passwords do not compare, %v", err)
	}

	digest_uri := fmt.Sprintf("bcrypt://?digest=%s&salt=%s", p.Digest(), p.Salt())

	p2, err := NewPassword(ctx, digest_uri)

	if err != nil {
		t.Fatalf("Failed to create password from digest, %v", err)
	}

	err = p2.Compare("s33kret99")

	if err != nil {
		t.Fatalf("Passwords (p2) do not compare, %v", err)
	}

	p3, err := NewBCryptPasswordFromDigest(p.Digest(), p.Salt())

	if err != nil {
		t.Fatalf("Failed to create password from digest (p3), %v", err)
	}

	if err := p3.Compare("s33kret99"); err != nil {
		t.Fatalf("Passwords (p3) do not compare, %v", err)
	}
}

func TestBCrypt(t *testing.T) {

	ctx := context.Background()

	raw, err := NewRandomPassword()

	if err != nil {
		t.Fatal(err)
	}

	salt, err := NewSalt()

	if err != nil {
		t.Fatal(err)
	}

	uri := fmt.Sprintf("bcrypt://%s?salt=%s", raw, salt)
	pswd, err := NewPassword(ctx, uri)

	if err != nil {
		t.Fatal(err)
	}

	err = pswd.Compare(raw)

	if err != nil {
		t.Fatal(err)
	}

	if pswd.Compare(raw+"x") == nil {
		t.Fatal("Wrong password matched")
	}
}

func TestBCryptRoundTrip(t *testing.T) {

	ctx := context.Background()

	raw := "p@ss/w0rd?#&+% é"

	pswd, err := NewPassword(ctx, "bcrypt:///?password="+url.QueryEscape(raw)+"&cost=4")

	if err != nil {
		t.Fatal(err)
	}

	pswd2, err := NewPassword(ctx, pswd.String())

	if err != nil {
		t.Fatal(err)
	}

	if pswd2.Salt() != pswd.Salt() || pswd2.Digest() != pswd.Digest() {
		t.Fatal("String() did not round trip")
	}

	if err := pswd2.Compare(raw); err != nil {
		t.Fatal(err)
	}
}

func TestBCryptPepper(t *testing.T) {

	ctx := context.Background()

	pswd, err := NewPassword(ctx, "bcrypt:///?password=correct-horse&pepper=s3cret&cost=4")

	if err != nil {
		t.Fatal(err)
	}

	q := url.Values{}
	q.Set("digest", pswd.Digest())
	q.Set("salt", pswd.Salt())

	without, err := NewPassword(ctx, "bcrypt:///?"+q.Encode())

	if err != nil {
		t.Fatal(err)
	}

	if without.Compare("correct-horse") == nil {
		t.Fatal("Matched without the pepper")
	}

	q.Set("pepper", "s3cret")

	with, err := NewPassword(ctx, "bcrypt:///?"+q.Encode())

	if err != nil {
		t.Fatal(err)
	}

	if err := with.Compare("correct-horse"); err != nil {
		t.Fatal(err)
	}
}

func TestBCryptInvalid(t *testing.T) {

	ctx := context.Background()

	for _, uri := range []string{
		"bcrypt://abcd/efghijkl",                 // would be truncated
		"bcrypt://short",                         // too short
		"bcrypt:///?digest=abc",                  // digest without salt
		"bcrypt:///?password=longenough&cost=99", // invalid cost
	} {
		if _, err := NewPassword(ctx, uri); err == nil {
			t.Fatalf("Expected error for %s", uri)
		}
	}
}
