package envx

import (
	"os"
	"path/filepath"
	"testing"
)

// payloadVersion returns the wire-version byte of an encrypted_pqc value.
func payloadVersion(t *testing.T, enc string) byte {
	t.Helper()
	payload, err := decodePayloadForTest(enc)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if len(payload) == 0 {
		t.Fatal("empty payload")
	}
	return payload[0]
}

// EncryptFile must upgrade legacy v1 ciphertext to the v2 AAD-bound format when a
// private key is available (matching the documented `envx encrypt` upgrade path),
// while still decrypting to the original plaintext.
func TestEncryptFile_UpgradesLegacyV1ToV2(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	legacy, err := encryptLegacyForTest("legacy-secret", pub)
	if err != nil {
		t.Fatal(err)
	}
	if payloadVersion(t, legacy) != pqcWireVersionLegacy {
		t.Fatalf("fixture is not v1")
	}

	content := "DOTENV_PUBLIC_KEY=" + quote(pub) + "\nSECRET=" + quote(legacy) + "\n"
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.keys"), []byte("DOTENV_PRIVATE_KEY="+quote(priv)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := EncryptFile(EncryptFileOptions{File: envPath}); err != nil {
		t.Fatal(err)
	}

	// The on-disk value must now be a v2 (AAD-bound) payload, not the legacy one.
	raw, err := DecryptFile(DecryptFileOptions{File: envPath})
	if err != nil {
		t.Fatal(err)
	}
	if raw["SECRET"] != "legacy-secret" {
		t.Fatalf("SECRET=%q after upgrade", raw["SECRET"])
	}

	values, err := readDotenvFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := payloadVersion(t, values["SECRET"]); got != pqcWireVersion {
		t.Fatalf("expected v%d after upgrade, got v%d", pqcWireVersion, got)
	}
	if isLegacyEncrypted(values["SECRET"]) {
		t.Fatal("value still reports as legacy v1 after upgrade")
	}
}

// Without a private key, a legacy v1 value cannot be upgraded and must be left
// exactly as-is (no error, no rewrite).
func TestEncryptFile_LeavesLegacyV1WhenNoKey(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	pub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := encryptLegacyForTest("still-v1", pub)
	if err != nil {
		t.Fatal(err)
	}

	content := "DOTENV_PUBLIC_KEY=" + quote(pub) + "\nSECRET=" + quote(legacy) + "\n"
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// No .env.keys, and the matching env var must be absent.
	t.Setenv("DOTENV_PRIVATE_KEY", "")

	if err := EncryptFile(EncryptFileOptions{File: envPath}); err != nil {
		t.Fatal(err)
	}

	values, err := readDotenvFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := payloadVersion(t, values["SECRET"]); got != pqcWireVersionLegacy {
		t.Fatalf("legacy value must be left untouched without a key, got v%d", got)
	}
}

// Re-encrypting a file whose values are already v2 must not rewrite them: AES-GCM
// and ML-KEM are randomized, so churn here would mean a needless diff on every run.
func TestEncryptFile_DoesNotChurnExistingV2(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	v2, err := Encrypt("bound-value", pub, EncryptionContext{VarName: "SECRET", PublicKeyVar: "DOTENV_PUBLIC_KEY"})
	if err != nil {
		t.Fatal(err)
	}

	content := "DOTENV_PUBLIC_KEY=" + quote(pub) + "\nSECRET=" + quote(v2) + "\n"
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.keys"), []byte("DOTENV_PRIVATE_KEY="+quote(priv)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(EncryptFileOptions{File: envPath}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("v2 file changed across re-encrypt:\nbefore=%q\nafter =%q", before, after)
	}
}
