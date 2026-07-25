package vnstat

import "testing"

func TestNewDisabled(t *testing.T) {
	provider, err := New(false, "", "")
	if err != nil || provider != nil {
		t.Fatalf("New(false) = %#v, %v", provider, err)
	}
}

func TestNewMissingBinaryIsOptional(t *testing.T) {
	provider, err := New(true, "definitely-not-vnstat", "")
	if err != nil || provider != nil {
		t.Fatalf("New(missing) = %#v, %v", provider, err)
	}
}
