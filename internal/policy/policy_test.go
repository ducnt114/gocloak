package policy

import "testing"

func TestPolicy(t *testing.T) {
	p, err := Parse("length(8) and digits(1) and upperCase(1) and specialChars(1) and notUsername(undefined) and passwordHistory(2) and hashAlgorithm(pbkdf2-sha256) and hashIterations(1000)")
	if err != nil {
		t.Fatal(err)
	}
	if p.History != 2 || p.HashAlgorithm != "pbkdf2-sha256" || p.HashIterations != 1000 {
		t.Fatalf("parsed %+v", p)
	}
	cases := map[string]string{
		"short":      "invalidPasswordMinLengthMessage",
		"abcdefgh":   "invalidPasswordMinDigitsMessage",
		"abcdefg1":   "invalidPasswordMinUpperCaseCharsMessage",
		"Abcdefg1":   "invalidPasswordMinSpecialCharsMessage",
		"Abcdefg1!":  "",
		"Bob12345!x": "",
	}
	for pw, want := range cases {
		got := ""
		if e := p.Validate(pw, Subject{Username: "bob"}); e != nil {
			got = e.Key
		}
		if got != want {
			t.Errorf("%q: got %q want %q", pw, got, want)
		}
	}
	if e := p.Validate("Bob!2345", Subject{Username: "bob!2345"}); e == nil || e.Key != "invalidPasswordNotUsernameMessage" {
		t.Errorf("notUsername: %v", e)
	}
	if _, err := Parse("length(8) and nope(1)"); err == nil {
		t.Fatal("unknown policy accepted")
	}
	if e := (&Policy{MinLength: 8}).Validate("short", Subject{}); e.Message != "Invalid password: minimum length 8." {
		t.Fatalf("message = %q", e.Message)
	}
}
