package password

import (
	"context"
	"fmt"
	"testing"
)

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

	// fmt.Println(pswd)
}
