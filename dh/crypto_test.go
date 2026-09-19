package dh

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGetDeviceKey(t *testing.T) {
	// The protocol specifies: MD5("user:Login to SALT:pass"), uppercase hex.
	// Verify against a fresh MD5 so we catch accidental changes to the salt
	// placement or the "Login to" separator string.
	user, pass, salt := "admin", "hunter2", "abc123"
	raw := user + ":Login to " + salt + ":" + pass
	sum := md5.Sum([]byte(raw))
	want := strings.ToUpper(hex.EncodeToString(sum[:]))

	got := GetDeviceKey(user, pass, salt)
	if string(got) != want {
		t.Fatalf("GetDeviceKey mismatch\n got: %s\nwant: %s", got, want)
	}
	if len(got) != 32 {
		t.Fatalf("GetDeviceKey: want 32 hex chars, got %d", len(got))
	}
	// All characters should be uppercase hex
	for _, c := range string(got) {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			t.Fatalf("non-uppercase-hex char %q in %s", c, got)
		}
	}
}

func TestEncryptDecryptAddrRoundTrip(t *testing.T) {
	key := GetDeviceKey("admin", "password", "SALT1")
	nonce := 12345
	plain := "127.0.0.1:49300"

	ct, err := EncryptAddr(key, nonce, plain)
	if err != nil {
		t.Fatalf("EncryptAddr: %v", err)
	}
	if ct == plain {
		t.Fatalf("ciphertext equals plaintext (not encrypted?)")
	}

	pt, err := DecryptAddr(key, nonce, ct)
	if err != nil {
		t.Fatalf("DecryptAddr: %v", err)
	}
	if pt != plain {
		t.Fatalf("roundtrip mismatch: got %q, want %q", pt, plain)
	}
}

func TestDecryptAddrWrongNonceFails(t *testing.T) {
	key := GetDeviceKey("admin", "password", "SALT1")
	plain := "10.0.0.1:8080"

	ct, err := EncryptAddr(key, 42, plain)
	if err != nil {
		t.Fatalf("EncryptAddr: %v", err)
	}
	pt, err := DecryptAddr(key, 43, ct)
	if err != nil {
		// Decryption might succeed (stream cipher) but produce garbage.
		return
	}
	if pt == plain {
		t.Fatalf("decryption with wrong nonce returned plaintext")
	}
}

func TestPBKDF2SHA256KnownVector(t *testing.T) {
	// RFC 7914 / RFC 6070-style check vectors aren't given for SHA-256, so
	// use a value we can compute: deriving a 32-byte key with 1 iteration
	// should equal HMAC-SHA256(password, salt || 0x00000001).
	password := []byte("password")
	salt := []byte("salt")
	got := pbkdf2SHA256(password, salt, 1, 32)
	if len(got) != 32 {
		t.Fatalf("length: got %d, want 32", len(got))
	}
	// Known output for PBKDF2-HMAC-SHA256("password", "salt", 1, 32)
	// from RFC 7914 test vectors.
	want, _ := hex.DecodeString("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
	if string(got) != string(want) {
		t.Fatalf("pbkdf2 mismatch\n got: %x\nwant: %x", got, want)
	}
}

func TestPBKDF2SHA256MultipleIterations(t *testing.T) {
	// RFC 7914: PBKDF2-HMAC-SHA256("password", "salt", 2, 32)
	// = ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43
	got := pbkdf2SHA256([]byte("password"), []byte("salt"), 2, 32)
	want, _ := hex.DecodeString("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
	if string(got) != string(want) {
		t.Fatalf("pbkdf2 2-iter mismatch\n got: %x\nwant: %x", got, want)
	}
}

func TestDecryptDeviceInfoBadBase64(t *testing.T) {
	if _, err := DecryptDeviceInfo("!!!not base64!!!"); err == nil {
		t.Fatalf("expected error for bad base64")
	}
}

func TestGetDeviceNonceNonZero(t *testing.T) {
	// Trivial sanity: 4 random bytes packed into int shouldn't always be 0.
	sawNonZero := false
	for i := 0; i < 20; i++ {
		if GetDeviceNonce() != 0 {
			sawNonZero = true
			break
		}
	}
	if !sawNonZero {
		t.Fatalf("GetDeviceNonce() returned 0 twenty times in a row")
	}
}
