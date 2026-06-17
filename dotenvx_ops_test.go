package envx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Operational-security invariants (complement crypto vectors):
// - Ephemeral randomness: same plaintext must not produce identical ciphertext (unlinkability / no trivial fingerprinting).
// - Key material from .env.keys is used only for decryption and must not be merged into the same map as app config (least privilege / separation).
// - Multiple comma-separated private keys: supported for rotation / phased cutover without downtime.

func TestOperationalSecurity_SamePlaintextYieldsDistinctCiphertexts(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	plain := "guessable-or-repeated-secret"
	ctx := EncryptionContext{VarName: "SECRET", PublicKeyVar: "DOTENV_PUBLIC_KEY"}

	a, err := Encrypt(plain, pub, ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(plain, pub, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two encryptions of the same plaintext must differ: ML-KEM encapsulation uses fresh randomness so ciphertext is not deterministic")
	}

	decA, err := DecryptIfEncrypted(a, []string{priv}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	decB, err := DecryptIfEncrypted(b, []string{priv}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if decA != plain || decB != plain {
		t.Fatalf("decrypt mismatch: %q / %q", decA, decB)
	}
}

func TestOperationalSecurity_PrivateKeyFromEnvKeysNotMergedIntoLoadedValues(t *testing.T) {
	dir := t.TempDir()

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := Encrypt("payload", pub, EncryptionContext{VarName: "APP", PublicKeyVar: "DOTENV_PUBLIC_KEY"})
	if err != nil {
		t.Fatal(err)
	}

	envPath := filepath.Join(dir, ".env")
	keysPath := filepath.Join(dir, ".env.keys")
	if err := os.WriteFile(envPath, []byte("DOTENV_PUBLIC_KEY="+quote(pub)+"\nAPP="+quote(enc)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysPath, []byte("DOTENV_PRIVATE_KEY="+quote(priv)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	values, err := Load(&LoadOptions{Files: []string{envPath}, Overload: false})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := values["DOTENV_PRIVATE_KEY"]; ok {
		t.Fatal("private key from .env.keys must not be copied into merged env values; keep decryption keys out of application config")
	}
	if values["APP"] != "payload" {
		t.Fatalf("APP=%q", values["APP"])
	}
}

func TestOperationalSecurity_CommaSeparatedPrivateKeys_DecryptsWithValidKeyInList(t *testing.T) {
	pub, privGood, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, privWrong, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	plain := "rotation-scenario"
	ctx := EncryptionContext{VarName: "ROTATED", PublicKeyVar: "DOTENV_PUBLIC_KEY"}
	enc, err := Encrypt(plain, pub, ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Same format as DOTENV_PRIVATE_KEY="old,new" in ops / CI.
	combined := privWrong + "," + privGood
	got, err := DecryptIfEncrypted(enc, strings.Split(combined, ","), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Fatalf("got %q", got)
	}
}
