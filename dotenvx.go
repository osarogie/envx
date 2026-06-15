package envx

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/joho/godotenv"
)

type LoadOptions struct {
	// Files are read in order; later files override earlier ones.
	Files []string

	// Overload controls whether loaded values override pre-existing environment variables.
	Overload bool
}

// MergeDotenvFiles reads dotenv files in order and returns the merged map (later files override).
// Encrypted `encrypted_pqc:` values are decrypted using LookupPrivateKeys per file.
// It does not modify the process environment.
func MergeDotenvFiles(files []string) (map[string]string, error) {
	if len(files) == 0 {
		return map[string]string{}, nil
	}

	merged := map[string]string{}

	for _, f := range files {
		if strings.TrimSpace(f) == "" {
			continue
		}

		values, err := readDotenvFile(f)
		if err != nil {
			return nil, err
		}

		privateKeys, keysErr := LookupPrivateKeys(f)
		hasEncrypted := false
		for k, v := range values {
			if strings.HasPrefix(v, encryptedPrefix) {
				hasEncrypted = true
				dec, derr := DecryptIfEncrypted(v, privateKeys)
				if derr != nil {
					if errors.Is(keysErr, ErrMissingPrivateKey) {
						return nil, ErrMissingPrivateKey
					}
					return nil, derr
				}
				values[k] = dec
			}
		}
		if hasEncrypted && keysErr != nil && errors.Is(keysErr, ErrMissingPrivateKey) {
			return nil, ErrMissingPrivateKey
		}

		for k, v := range values {
			merged[k] = v
		}
	}

	return merged, nil
}

// EnvironMergedKeys returns a copy of baseEnviron (typically os.Environ()) where each listed key
// is set to merged[key] when merged contains that key. Keys present in merged but not listed are
// not applied—use this to pass a minimal env to a child process (e.g. only database URLs for Atlas).
//
// When overload is false, an existing variable in baseEnviron keeps its value (same rule as
// LoadOptions.Overload for dotenv): runtime secrets from the orchestrator win over committed files.
// When overload is true, merged values always replace base for listed keys.
func EnvironMergedKeys(baseEnviron []string, merged map[string]string, keys []string, overload bool) []string {
	out := append([]string{}, baseEnviron...)
	idx := make(map[string]int)
	for i, kv := range out {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, seen := idx[k]; !seen {
			idx[k] = i
		}
	}
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		v, ok := merged[key]
		if !ok {
			continue
		}
		if !overload {
			if _, exists := idx[key]; exists {
				continue
			}
		}
		pair := key + "=" + v
		if i, exists := idx[key]; exists {
			out[i] = pair
		} else {
			out = append(out, pair)
			idx[key] = len(out) - 1
		}
	}
	return out
}

// environToMap parses KEY=value lines (first '=' separates key from value).
func environToMap(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			m[kv] = ""
			continue
		}
		m[k] = v
	}
	return m
}

func deletePrivateKeyEnvVars(m map[string]string) {
	for k := range m {
		if k == "DOTENV_PRIVATE_KEY" || strings.HasPrefix(k, "DOTENV_PRIVATE_KEY_") {
			delete(m, k)
		}
	}
}

func mapToSortedEnviron(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}

// EnvironWithMergedOverlay returns base environ with DOTENV_PRIVATE_KEY* removed, then merged
// keys applied (except private-key vars) according to overload. Use for
// `dotenvx run --inject-all-merged` so the child receives decrypted dotenv without loading
// secrets into the parent process.
//
// When overload is false (default), keys already present in baseEnviron keep their value and
// merged only fills in keys baseEnviron does not set: runtime secrets from the orchestrator
// (docker compose `environment:`, kamal `env.secret:`) win over committed .env files. When
// overload is true, merged values replace any baseEnviron entry for the same key. This matches
// EnvironMergedKeys' semantics — without it, an encrypted REDIS_URL in .env.development
// silently overrides the redis URL the orchestrator passes, so workers and the dashboard end
// up on different Redis instances.
func EnvironWithMergedOverlay(baseEnviron []string, merged map[string]string, overload bool) []string {
	m := environToMap(baseEnviron)
	deletePrivateKeyEnvVars(m)
	for k, v := range merged {
		if k == "DOTENV_PRIVATE_KEY" || strings.HasPrefix(k, "DOTENV_PRIVATE_KEY_") {
			continue
		}
		if !overload {
			if _, exists := m[k]; exists {
				continue
			}
		}
		m[k] = v
	}
	return mapToSortedEnviron(m)
}

// Load reads dotenv files and applies them to the current process environment.
// It returns the merged key/value map (after file-to-file overrides are applied).
//
// opts may be nil: default is Overload false and a file list from
// DiscoverEnvFilesWithPrivateKeysInEnv (cwd files named `.env` or `.env.*` except `.env.keys`,
// where the matching DOTENV_PRIVATE_KEY / DOTENV_PRIVATE_KEY_* is set in the environment).
// If opts.Files is non-nil but empty, the same default file list is used.
func Load(opts *LoadOptions) (map[string]string, error) {
	var files []string
	var overload bool
	if opts != nil {
		files = opts.Files
		overload = opts.Overload
	}
	if len(files) == 0 {
		files = DiscoverEnvFilesWithPrivateKeysInEnv()
	}
	merged, err := MergeDotenvFiles(files)
	if err != nil {
		return nil, err
	}
	applyToEnv(merged, overload)
	UnsetDotenvPrivateKeysFromEnv()
	return merged, nil
}

// DiscoverEnvFilesWithPrivateKeysInEnv returns absolute paths under the current working directory
// for `.env` and `.env.*` files (excluding `.env.keys`) such that the corresponding
// DOTENV_PRIVATE_KEY variable is set in the process environment to a non-empty key (after parsing).
// Order: `.env` first if selected, then other names sorted lexicographically.
func DiscoverEnvFilesWithPrivateKeysInEnv() []string {
	wd, err := os.Getwd()
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(wd)
	if err != nil {
		return nil
	}

	var hasDotEnv bool
	var suffixed []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		switch {
		case name == ".env":
			hasDotEnv = true
		case name == ".env.keys":
			continue
		case strings.HasPrefix(name, ".env."):
			suffixed = append(suffixed, name)
		}
	}
	sort.Strings(suffixed)

	names := make([]string, 0, 1+len(suffixed))
	if hasDotEnv {
		names = append(names, ".env")
	}
	names = append(names, suffixed...)

	out := make([]string, 0, len(names))
	for _, name := range names {
		path := filepath.Join(wd, name)
		keyVar := PrivateKeyVarForEnvFile(path)
		v, ok := os.LookupEnv(keyVar)
		if !ok || len(parsePrivateKeysList(v)) == 0 {
			continue
		}
		out = append(out, path)
	}
	return out
}

func readDotenvFile(path string) (map[string]string, error) {
	// dotenvx treats missing files as non-fatal in many contexts; we follow that.
	// If the path exists but can't be read/parsed, return an error.
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
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

func applyToEnv(values map[string]string, overload bool) {
	if overload {
		for k, v := range values {
			_ = os.Setenv(k, v)
		}
		return
	}

	for k, v := range values {
		if _, exists := os.LookupEnv(k); exists {
			continue
		}
		_ = os.Setenv(k, v)
	}
}

// FilesFromPrivateKeys returns dotenv file paths inferred from the current environment,
// based on DOTENV_PRIVATE_KEY conventions:
// - DOTENV_PRIVATE_KEY -> ".env"
// - DOTENV_PRIVATE_KEY_PRODUCTION -> ".env.production"
// Underscores in the suffix become dots.
//
// Returned paths are relative to cwd, matching the upstream convention.
func FilesFromPrivateKeys(environ []string) []string {
	const prefix = "DOTENV_PRIVATE_KEY"
	type hit struct {
		suffix string
		path   string
	}

	hits := make([]hit, 0, 2)
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		// Match DiscoverEnvFilesWithPrivateKeysInEnv: ignore empty placeholders (e.g. Coolify
		// may set DOTENV_PRIVATE_KEY= with no material while DOTENV_PRIVATE_KEY_PRODUCTION is set).
		if k == prefix {
			if len(parsePrivateKeysList(v)) > 0 {
				hits = append(hits, hit{suffix: "", path: ".env"})
			}
			continue
		}
		if strings.HasPrefix(k, prefix+"_") {
			if len(parsePrivateKeysList(v)) == 0 {
				continue
			}
			suffix := strings.TrimPrefix(k, prefix+"_")
			// Upstream behavior: underscores become dots in filename.
			// Also normalize to lowercase because `.env.production` is the common convention.
			filenameSuffix := strings.ToLower(strings.ReplaceAll(suffix, "_", "."))
			hits = append(hits, hit{suffix: suffix, path: ".env." + filenameSuffix})
		}
	}

	sort.Slice(hits, func(i, j int) bool {
		// Stable, deterministic ordering:
		// - Prefer base `.env` first.
		// - Then sort by suffix name.
		if hits[i].suffix == "" && hits[j].suffix != "" {
			return true
		}
		if hits[i].suffix != "" && hits[j].suffix == "" {
			return false
		}
		return hits[i].suffix < hits[j].suffix
	})

	out := make([]string, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		p := filepath.Clean(h.path)
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	return out
}
