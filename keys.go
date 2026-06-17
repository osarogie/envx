package envx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
)

// PublicKeyVarForEnvFile maps a dotenv filename to its DOTENV_PUBLIC_KEY_* name in that file.
// Examples:
//
//	".env" -> "DOTENV_PUBLIC_KEY"
//	".env.production" -> "DOTENV_PUBLIC_KEY_PRODUCTION"
func PublicKeyVarForEnvFile(envFile string) string {
	base := filepath.Base(envFile)
	if base == ".env" {
		return "DOTENV_PUBLIC_KEY"
	}
	if strings.HasPrefix(base, ".env.") {
		suffix := strings.TrimPrefix(base, ".env.")
		suffix = strings.ToUpper(strings.ReplaceAll(suffix, ".", "_"))
		return "DOTENV_PUBLIC_KEY_" + suffix
	}
	return "DOTENV_PUBLIC_KEY"
}

// PrivateKeyVarForEnvFile maps a dotenv filename to its expected DOTENV_PRIVATE_KEY variable name.
// Examples:
//
//	".env" -> "DOTENV_PRIVATE_KEY"
//	".env.production" -> "DOTENV_PRIVATE_KEY_PRODUCTION"
func PrivateKeyVarForEnvFile(envFile string) string {
	base := filepath.Base(envFile)
	if base == ".env" {
		return "DOTENV_PRIVATE_KEY"
	}
	if strings.HasPrefix(base, ".env.") {
		suffix := strings.TrimPrefix(base, ".env.")
		suffix = strings.ToUpper(strings.ReplaceAll(suffix, ".", "_"))
		return "DOTENV_PRIVATE_KEY_" + suffix
	}
	return "DOTENV_PRIVATE_KEY"
}

// UnsetDotenvPrivateKeysFromEnv removes DOTENV_PRIVATE_KEY and DOTENV_PRIVATE_KEY_* from the
// process environment after values have been merged in memory, so other libraries and child
// processes started later cannot read decapsulation material from the environment.
func UnsetDotenvPrivateKeysFromEnv() {
	for _, kv := range os.Environ() {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if k == "DOTENV_PRIVATE_KEY" || strings.HasPrefix(k, "DOTENV_PRIVATE_KEY_") {
			_ = os.Unsetenv(k)
		}
	}
}

func parsePrivateKeysList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.Trim(p, `"'`))
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// LookupPrivateKeys returns private key(s) for a given env file, checking, in order:
//  1. the matching environment variable (DOTENV_PRIVATE_KEY*), supporting comma-separated keys
//  2. a `.env.keys` file located *adjacent to the target env file*
//
// It deliberately does NOT fall back to a `.env.keys` in the current working
// directory. Reading decapsulation material from the cwd is an injection risk:
// a process invoked from an attacker-influenced directory (or a repo checkout
// containing a planted `.env.keys`) could otherwise be tricked into using keys
// the operator never intended. Keys must come from the explicit environment
// variable or from a keys file sitting next to the dotenv file being decrypted.
func LookupPrivateKeys(envFile string) ([]string, error) {
	keyVar := PrivateKeyVarForEnvFile(envFile)

	if v, ok := os.LookupEnv(keyVar); ok {
		keys := parsePrivateKeysList(v)
		if len(keys) > 0 {
			return keys, nil
		}
	}

	// Only trust a `.env.keys` adjacent to the target env file. No cwd fallback.
	keysPath := filepath.Join(filepath.Dir(envFile), ".env.keys")
	m, err := readKeysFile(keysPath)
	if err != nil {
		return nil, err
	}
	if m != nil {
		if v, ok := m[keyVar]; ok {
			keys := parsePrivateKeysList(v)
			if len(keys) > 0 {
				return keys, nil
			}
		}
	}

	return nil, ErrMissingPrivateKey
}

func readKeysFile(path string) (map[string]string, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return godotenv.Parse(f)
}
