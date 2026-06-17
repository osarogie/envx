package envx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePlainDirectiveKeys(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"FOO=bar # dotenvx:plain\n", []string{"FOO"}},
		{"FOO=bar # DOTENVX:PLAIN\n", []string{"FOO"}},
		{"FOO=bar # note dotenvx-plain end\n", []string{"FOO"}},
		{"FOO=bar\n", nil},
		{"FOO=bar # not plain\n", nil},
		{"# dotenvx:plain\nFOO=bar\n", nil},
		{"export BAR=x # dotenvx:plain\n", []string{"BAR"}},
		{`QUOTED="a b" # dotenvx:plain` + "\n", []string{"QUOTED"}},
		{`QUOTED="a b # dotenvx:plain"` + "\n", nil},
	}
	for _, tc := range cases {
		got := parsePlainDirectiveKeys(tc.input)
		if len(got) != len(tc.want) {
			t.Fatalf("input %q: got %v want keys %v", tc.input, got, tc.want)
		}
		for _, k := range tc.want {
			if !got[k] {
				t.Fatalf("input %q: missing %q in %v", tc.input, k, got)
			}
		}
	}
}

func TestEncryptFile_plainDirectiveSkipsEncryption(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	content := "DOTENV_PUBLIC_KEY=" + quote(pub) + "\n" +
		"KEEP_PLAIN=visible # dotenvx:plain\n" +
		"SHOULD_ENC=secret\n"
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	keysPath := filepath.Join(dir, ".env.keys")
	if err := os.WriteFile(keysPath, []byte("DOTENV_PRIVATE_KEY="+quote(priv)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := EncryptFile(EncryptFileOptions{File: envPath}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, line := range strings.Split(s, "\n") {
		if !strings.Contains(line, "KEEP_PLAIN=") {
			continue
		}
		if strings.Contains(line, encryptedPrefix) {
			t.Fatalf("KEEP_PLAIN should not be encrypted: %q", line)
		}
		break
	}

	m, err := DecryptFile(DecryptFileOptions{File: envPath})
	if err != nil {
		t.Fatal(err)
	}
	if m["KEEP_PLAIN"] != "visible" {
		t.Fatalf("KEEP_PLAIN=%q", m["KEEP_PLAIN"])
	}
	if m["SHOULD_ENC"] != "secret" {
		t.Fatalf("SHOULD_ENC=%q", m["SHOULD_ENC"])
	}
}

func TestEncryptFile_plainDirectiveDecryptsPreviouslyEncrypted(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	// Seal with the context EncryptFile reconstructs for REV so the dotenvx:plain
	// decrypt path can recover it.
	enc, err := Encrypt("was-secret", pub, EncryptionContext{VarName: "REV", PublicKeyVar: "DOTENV_PUBLIC_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	content := "DOTENV_PUBLIC_KEY=" + quote(pub) + "\n" +
		"REV=" + quote(enc) + " # dotenvx:plain\n"
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	keysPath := filepath.Join(dir, ".env.keys")
	if err := os.WriteFile(keysPath, []byte("DOTENV_PRIVATE_KEY="+quote(priv)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := EncryptFile(EncryptFileOptions{File: envPath}); err != nil {
		t.Fatal(err)
	}

	m, err := DecryptFile(DecryptFileOptions{File: envPath})
	if err != nil {
		t.Fatal(err)
	}
	if m["REV"] != "was-secret" {
		t.Fatalf("REV=%q", m["REV"])
	}
	raw, _ := os.ReadFile(envPath)
	if strings.Contains(string(raw), encryptedPrefix) && strings.Contains(string(raw), "REV") {
		t.Fatal("REV should have been written back as plaintext")
	}
}
