package envx

import (
	"crypto/mlkem"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) error {
	t.Helper()
	return os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
}

func decodePayloadForTest(enc string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimPrefix(enc, encryptedPrefix))
}

// encryptLegacyForTest produces a wire-version-1 (pre-AAD) payload: sealed without
// additional authenticated data, so it mirrors values written before context binding.
func encryptLegacyForTest(plaintext, pubB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil {
		return "", err
	}
	ek, err := mlkem.NewEncapsulationKey768(raw)
	if err != nil {
		return "", err
	}
	payload, err := encryptPQCPayload([]byte(plaintext), ek, nil)
	if err != nil {
		return "", err
	}
	payload[0] = pqcWireVersionLegacy
	return encryptedPrefix + base64.StdEncoding.EncodeToString(payload), nil
}

// These tests pin the context-binding (AAD) hardening: a value sealed for one
// (variable, public-key-var) position must not decrypt when presented under a
// different position, and must round-trip when the context matches.

func TestAAD_RoundTripWithMatchingContext(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ctx := EncryptionContext{VarName: "DATABASE_URL", PublicKeyVar: "DOTENV_PUBLIC_KEY_PRODUCTION"}

	enc, err := Encrypt("postgres://secret", pub, ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptIfEncrypted(enc, []string{priv}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != "postgres://secret" {
		t.Fatalf("got %q", got)
	}
}

func TestAAD_WrongVarNameFailsToDecrypt(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := Encrypt("topsecret", pub, EncryptionContext{VarName: "API_KEY", PublicKeyVar: "DOTENV_PUBLIC_KEY"})
	if err != nil {
		t.Fatal(err)
	}

	// Same key, same file, but the ciphertext was moved to a different variable.
	_, err = DecryptIfEncrypted(enc, []string{priv}, EncryptionContext{VarName: "OTHER_KEY", PublicKeyVar: "DOTENV_PUBLIC_KEY"})
	if err == nil {
		t.Fatal("ciphertext bound to API_KEY must not decrypt as OTHER_KEY")
	}
}

func TestAAD_WrongPublicKeyVarFailsToDecrypt(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := Encrypt("topsecret", pub, EncryptionContext{VarName: "API_KEY", PublicKeyVar: "DOTENV_PUBLIC_KEY"})
	if err != nil {
		t.Fatal(err)
	}

	// Same variable name, but copied into a different env file (different public-key var).
	_, err = DecryptIfEncrypted(enc, []string{priv}, EncryptionContext{VarName: "API_KEY", PublicKeyVar: "DOTENV_PUBLIC_KEY_PRODUCTION"})
	if err == nil {
		t.Fatal("ciphertext bound to .env must not decrypt under .env.production's public-key var")
	}
}

// TestAAD_CrossFileSwapDetectedThroughDecryptFile exercises the binding end-to-end:
// a sealed value valid in one env file is rejected when pasted into another file
// (whose values use a different DOTENV_PUBLIC_KEY_* name), even with the right key.
func TestAAD_CrossFileSwapDetectedThroughDecryptFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	// Seal for the base .env file's DATABASE_URL.
	enc, err := Encrypt("postgres://prod", pub, EncryptionContext{VarName: "DATABASE_URL", PublicKeyVar: "DOTENV_PUBLIC_KEY"})
	if err != nil {
		t.Fatal(err)
	}

	// Attacker copies the ciphertext into .env.production, reusing the same key pair.
	prodEnv := "DOTENV_PUBLIC_KEY_PRODUCTION=" + quote(pub) + "\nDATABASE_URL=" + quote(enc) + "\n"
	if err := writeFile(t, dir, ".env.production", prodEnv); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(t, dir, ".env.keys", "DOTENV_PRIVATE_KEY_PRODUCTION="+quote(priv)+"\n"); err != nil {
		t.Fatal(err)
	}

	if _, err := DecryptFile(DecryptFileOptions{File: ".env.production"}); err == nil {
		t.Fatal("value sealed for .env (DOTENV_PUBLIC_KEY) must not decrypt inside .env.production")
	}
}

// TestAAD_LegacyV1CiphertextStillDecrypts guards backward compatibility: payloads
// sealed before context binding (wire version 1, no AAD) must still decrypt so
// existing encrypted files keep working until re-encrypted.
func TestAAD_LegacyV1CiphertextStillDecrypts(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	legacy, err := encryptLegacyForTest("legacy-value", pub)
	if err != nil {
		t.Fatal(err)
	}

	// Any context is ignored for legacy payloads.
	got, err := DecryptIfEncrypted(legacy, []string{priv}, EncryptionContext{VarName: "WHATEVER", PublicKeyVar: "DOTENV_PUBLIC_KEY"})
	if err != nil {
		t.Fatalf("legacy v1 ciphertext should still decrypt: %v", err)
	}
	if got != "legacy-value" {
		t.Fatalf("got %q", got)
	}
}

func TestEncryptionContextAAD_LengthPrefixingAvoidsCollisions(t *testing.T) {
	// {VarName:"BC", PublicKeyVar:"A"} and {VarName:"C", PublicKeyVar:"AB"} share the
	// naive concatenation "A"+"BC" == "AB"+"C"; length-prefixing must keep them distinct.
	a := EncryptionContext{PublicKeyVar: "A", VarName: "BC"}.aad()
	b := EncryptionContext{PublicKeyVar: "AB", VarName: "C"}.aad()
	if string(a) == string(b) {
		t.Fatal("distinct contexts produced identical AAD; encoding is ambiguous")
	}
}

func TestAAD_TamperedVersionByteRejected(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ctx := EncryptionContext{VarName: "X", PublicKeyVar: "DOTENV_PUBLIC_KEY"}
	enc, err := Encrypt("v", pub, ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a current (v2) payload's version byte to an unknown value and confirm rejection.
	payload, err := decodePayloadForTest(enc)
	if err != nil {
		t.Fatal(err)
	}
	payload[0] = 0x7f
	if _, err := decryptPQCPayload(payload, priv, ctx); err == nil {
		t.Fatal("unknown wire version must be rejected")
	}
	if !strings.HasPrefix(enc, encryptedPrefix) {
		t.Fatalf("encrypted value lost its prefix: %q", enc)
	}
}
