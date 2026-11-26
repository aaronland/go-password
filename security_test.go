package password

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

const secret_pswd = "s3cr3t\x7fpassw0rd"

// A malformed escape must be an error, not a silently dropped parameter.
const bad_escape = "s3cr3t%zzpassw0rd"

// Malformed URIs must not echo the plain text password or pepper in errors.
func TestParseErrorsDoNotLeakSecrets(t *testing.T) {

	ctx := context.Background()

	uris := []string{
		"bcrypt:///?password=" + secret_pswd,
		"bcrypt:///?password=correcthorse&pepper=" + secret_pswd,
		"argon2id:///?password=" + secret_pswd,
	}

	for _, uri := range uris {

		_, err := NewPassword(ctx, uri)

		if err == nil {
			t.Fatalf("Expected error for %s", uri)
		}

		if strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "correcthorse") {
			t.Fatalf("Error leaks secret: %v", err)
		}
	}

	for _, uri := range []string{
		"bcrypt:///?password=correcthorse&pepper=" + bad_escape,
		"bcrypt:///?password=" + bad_escape,
		"argon2id:///?password=" + bad_escape,
	} {

		_, err := NewPassword(ctx, uri)

		if err == nil {
			t.Fatalf("Expected malformed escape to be rejected for %s", uri)
		}

		if strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "%zz") {
			t.Fatalf("Error leaks secret: %v", err)
		}
	}

	for _, f := range []PasswordInitializationFunc{NewBCryptPassword, NewArgon2idPassword} {

		_, err := f(ctx, "bcrypt:///?password="+secret_pswd)

		if err == nil {
			t.Fatal("Expected error")
		}

		if strings.Contains(err.Error(), "s3cr3t") {
			t.Fatalf("Error leaks secret: %v", err)
		}
	}
}

// A host-form password followed by a query string must be rejected, not truncated.
func TestHostPasswordNotTruncatedAtQuery(t *testing.T) {

	ctx := context.Background()

	uris := []string{
		"bcrypt://correcthorse?battery",
		"bcrypt://correcthorse?",
		"bcrypt://correcthorse?battery=staple",
		"argon2id://correcthorse?battery",
		"argon2id://correcthorse?",
	}

	for _, uri := range uris {

		_, err := NewPassword(ctx, uri)

		if err == nil {
			t.Fatalf("Expected %s to be rejected", uri)
		}
	}

	// Recognized parameters remain valid alongside a host password.
	_, err := NewPassword(ctx, "bcrypt://correcthorse?cost=4")

	if err != nil {
		t.Fatalf("Expected host password with cost to work, %v", err)
	}
}

// Argon2id hashes with excessive parameters must be rejected before Compare can run them.
func TestArgon2idRejectsExcessiveParameters(t *testing.T) {

	ctx := context.Background()

	salt := "c29tZXNhbHRzb21lc2FsdA"
	key := "c29tZWtleXNvbWVrZXlzb21la2V5c29tZWtleQ"

	hashes := []string{
		"$argon2id$v=19$m=4194304,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=65536,t=4000000000,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=65536,t=1,p=255$" + salt + "$" + key,
		"$argon2id$v=19$m=0,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=65536,t=0,p=1$" + salt + "$" + key,
	}

	for _, h := range hashes {

		q := url.Values{}
		q.Set("hash", h)

		_, err := NewPassword(ctx, "argon2id:///?"+q.Encode())

		if err == nil {
			t.Fatalf("Expected hash %s to be rejected", h)
		}
	}
}

// A bcrypt digest with an excessive cost must be rejected on load.
func TestBCryptRejectsExcessiveDigestCost(t *testing.T) {

	// A syntactically valid digest with cost 31; the hash portion is arbitrary.
	digest := "$2a$31$" + strings.Repeat("a", 53)

	_, err := NewBCryptPasswordFromDigest(digest, "somesalt")

	if err == nil {
		t.Fatal("Expected digest with cost 31 to be rejected")
	}

	_, err = NewBCryptPasswordFromDigest("not-a-digest", "somesalt")

	if err == nil {
		t.Fatal("Expected garbage digest to be rejected")
	}

	q := url.Values{}
	q.Set("digest", digest)
	q.Set("salt", "somesalt")

	_, err = NewPassword(context.Background(), "bcrypt:///?"+q.Encode())

	if err == nil {
		t.Fatal("Expected digest URI with cost 31 to be rejected")
	}

	// New hashes honour the same ceiling.
	_, err = NewPassword(context.Background(), "bcrypt:///?password=correcthorse&cost=31")

	if err == nil {
		t.Fatal("Expected cost 31 to be rejected for new hashes")
	}
}

// A digest with an acceptable cost still loads and verifies.
func TestBCryptAcceptsValidDigestCost(t *testing.T) {

	p, err := NewPassword(context.Background(), "bcrypt:///?password=correcthorse&cost="+strconv.Itoa(bcrypt.MinCost))

	if err != nil {
		t.Fatal(err)
	}

	p2, err := NewBCryptPasswordFromDigest(p.Digest(), p.Salt())

	if err != nil {
		t.Fatal(err)
	}

	if err := p2.Compare("correcthorse"); err != nil {
		t.Fatal(err)
	}
}
