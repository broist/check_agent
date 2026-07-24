package auth

import "testing"

func TestTokenHash(t *testing.T) {
	token := "0123456789abcdef0123456789abcdef"
	hash, err := HashToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyToken(token, hash) {
		t.Fatal("valid token rejected")
	}
	if VerifyToken(token+"x", hash) {
		t.Fatal("invalid token accepted")
	}
}
