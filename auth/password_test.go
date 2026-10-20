package auth

import "testing"

func TestPasswordRoundTrip(t *testing.T) {
	const password = "correct-horse-battery"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword(password, hash)
	if err != nil || !ok {
		t.Fatalf("verify matching password: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyPassword("correct-horse-batteries", hash)
	if err != nil || ok {
		t.Fatalf("verify wrong password: ok=%v err=%v", ok, err)
	}
	if _, err := HashPassword("short"); err != ErrPassword {
		t.Fatalf("short password error = %v", err)
	}
	if _, err := VerifyPassword(password, "$argon2id$v=19$m=99999999,t=1,p=1$c2FsdA$aGFzaA"); err == nil {
		t.Fatal("oversized hash parameters accepted")
	}
}
