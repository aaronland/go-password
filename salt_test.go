package password

import (
	"testing"
)

func TestSalt(t *testing.T) {

	_, err := NewSalt()
	
	if err != nil {
		t.Fatalf("Failed to create new salt, %w", err)
	}
	
}
