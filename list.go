package envx

import (
	"sort"
	"strings"
)

// KeyInfo describes a single assignment in a dotenv file.
type KeyInfo struct {
	Key string
	// Encrypted reports whether the stored value is an `encrypted_pqc:` payload.
	Encrypted bool
}

// ListKeys returns the keys defined in a dotenv file (sorted) along with whether
// each value is encrypted. It parses the file only — it does not decrypt and does
// not require a private key, so it is safe to run without DOTENV_PRIVATE_KEY*.
// A missing file yields an empty slice and no error (matching readDotenvFile).
func ListKeys(file string) ([]KeyInfo, error) {
	if strings.TrimSpace(file) == "" {
		file = ".env"
	}

	values, err := readDotenvFile(file)
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]KeyInfo, 0, len(keys))
	for _, k := range keys {
		out = append(out, KeyInfo{
			Key:       k,
			Encrypted: strings.HasPrefix(values[k], encryptedPrefix),
		})
	}
	return out, nil
}
