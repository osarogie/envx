package envx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// LookupPrivateKeys must only trust keys from the matching DOTENV_PRIVATE_KEY*
// environment variable or a `.env.keys` adjacent to the target env file. A planted
// `.env.keys` in the current working directory must never be consulted.

func TestLookupPrivateKeys_NoCwdFallback(t *testing.T) {
	// Target env file lives in its own directory with no adjacent .env.keys...
	targetDir := t.TempDir()
	envFile := filepath.Join(targetDir, ".env")

	// ...while the current working directory contains a (potentially attacker-planted)
	// .env.keys. It must be ignored.
	cwd := t.TempDir()
	t.Chdir(cwd)
	if err := os.WriteFile(filepath.Join(cwd, ".env.keys"), []byte("DOTENV_PRIVATE_KEY=\"planted-from-cwd\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LookupPrivateKeys(envFile)
	if !errors.Is(err, ErrMissingPrivateKey) {
		t.Fatalf("expected ErrMissingPrivateKey (cwd .env.keys must not be used), got %v", err)
	}
}

func TestLookupPrivateKeys_AdjacentKeysFileUsed(t *testing.T) {
	dir := t.TempDir()
	// Run from an unrelated cwd to prove the adjacent file (not cwd) is what's read.
	t.Chdir(t.TempDir())

	envFile := filepath.Join(dir, ".env.production")
	if err := os.WriteFile(filepath.Join(dir, ".env.keys"), []byte(`DOTENV_PRIVATE_KEY_PRODUCTION="adjacent-key"`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	keys, err := LookupPrivateKeys(envFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "adjacent-key" {
		t.Fatalf("expected adjacent key, got %v", keys)
	}
}

func TestLookupPrivateKeys_EnvVarTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(filepath.Join(dir, ".env.keys"), []byte(`DOTENV_PRIVATE_KEY="from-file"`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("DOTENV_PRIVATE_KEY", "from-env")

	keys, err := LookupPrivateKeys(envFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "from-env" {
		t.Fatalf("env var should win over adjacent .env.keys, got %v", keys)
	}
}

func TestLookupPrivateKeys_AdjacentResolvesWhenEnvFileIsRelativeCwd(t *testing.T) {
	// When the target file is given as a bare relative name, "adjacent" legitimately
	// resolves to the cwd — this is the intended single source, not the removed fallback.
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, ".env.keys"), []byte(`DOTENV_PRIVATE_KEY="local"`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	keys, err := LookupPrivateKeys(".env")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "local" {
		t.Fatalf("expected adjacent .env.keys for relative .env, got %v", keys)
	}
}
