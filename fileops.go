package envx

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/joho/godotenv"
)

type EncryptFileOptions struct {
	File string
}

type DecryptFileOptions struct {
	File string
}

// EncryptFile reads a dotenv file, ensures it has the env-specific DOTENV_PUBLIC_KEY_* (see PublicKeyVarForEnvFile),
// encrypts non-empty values, and writes it back. The public key line is always the first line of the file.
// It also ensures the corresponding DOTENV_PRIVATE_KEY* entry is present in `.env.keys`.
//
// An assignment may include an inline comment with "dotenvx:plain" or "dotenvx-plain" (case-insensitive); that key
// is left as plaintext. If the value was already encrypted, it is decrypted when rewriting.
func EncryptFile(opts EncryptFileOptions) error {
	file := opts.File
	if strings.TrimSpace(file) == "" {
		file = ".env"
	}
	file = filepath.Clean(file)
	pubVar := PublicKeyVarForEnvFile(file)

	raw, err := os.ReadFile(file)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	content := ""
	if err == nil {
		content = string(raw)
	}

	values, err := godotenv.Unmarshal(content)
	if err != nil {
		return err
	}

	// Migrate plain DOTENV_PUBLIC_KEY to env-specific name when the file uses a suffixed var.
	if pubVar != "DOTENV_PUBLIC_KEY" {
		if v, ok := values["DOTENV_PUBLIC_KEY"]; ok && strings.TrimSpace(values[pubVar]) == "" {
			values[pubVar] = v
			delete(values, "DOTENV_PUBLIC_KEY")
			content = stripAssignmentLineForKey(content, "DOTENV_PUBLIC_KEY")
		}
	}

	pubKey := strings.TrimSpace(strings.Trim(values[pubVar], `"'`))
	var privKey string
	var privateKeys []string
	if pubKey == "" {
		var genErr error
		pubKey, privKey, genErr = GenerateKeypair()
		if genErr != nil {
			return genErr
		}
		values[pubVar] = pubKey
		privateKeys = []string{privKey}
	} else {
		// Private key is only required if we have to decrypt something
		// (a `dotenvx:plain` directive that was previously encrypted).
		// Pure encryption of new plaintext values uses only the public
		// key, so a missing private key here is not fatal yet.
		var err error
		privateKeys, err = LookupPrivateKeys(file)
		if err != nil && !errors.Is(err, ErrMissingPrivateKey) {
			return err
		}
		if len(privateKeys) > 0 {
			privKey = privateKeys[0]
		}
	}

	plainKeys := parsePlainDirectiveKeys(content)

	for k, v := range values {
		if k == pubVar || k == "DOTENV_PUBLIC_KEY" || v == "" {
			continue
		}
		if strings.HasPrefix(v, encryptedPrefix) {
			if plainKeys[k] {
				if len(privateKeys) == 0 {
					return ErrMissingPrivateKey
				}
				dec, err := DecryptIfEncrypted(v, privateKeys, contextForFileVar(file, k))
				if err != nil {
					return err
				}
				values[k] = dec
			}
			continue
		}
		if plainKeys[k] {
			continue
		}
		enc, err := Encrypt(v, pubKey, EncryptionContext{VarName: k, PublicKeyVar: pubVar})
		if err != nil {
			return err
		}
		values[k] = enc
	}

	out, err := encryptPreservingLayout(content, values, file)
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, []byte(out), 0o600); err != nil {
		return err
	}

	// Only touch .env.keys if we actually generated a new keypair; without
	// a new private key there is nothing to persist (and we may not even
	// have one available at this point).
	if privKey == "" {
		return nil
	}
	return ensurePrivateKeyInKeysFile(file, privKey)
}

// DecryptFile returns the decrypted key/value map for a dotenv file.
func DecryptFile(opts DecryptFileOptions) (map[string]string, error) {
	file := opts.File
	if strings.TrimSpace(file) == "" {
		file = ".env"
	}

	values, err := readDotenvFile(file)
	if err != nil {
		return nil, err
	}

	privateKeys, err := LookupPrivateKeys(file)
	if err != nil {
		needs := false
		for _, v := range values {
			if strings.HasPrefix(v, encryptedPrefix) {
				needs = true
				break
			}
		}
		if needs {
			return nil, err
		}
		privateKeys = nil
	}

	for k, v := range values {
		if !strings.HasPrefix(v, encryptedPrefix) {
			continue
		}
		dec, derr := DecryptIfEncrypted(v, privateKeys, contextForFileVar(file, k))
		if derr != nil {
			return nil, derr
		}
		values[k] = dec
	}

	return values, nil
}

func escapeDoubleQuotes(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

func ensurePrivateKeyInKeysFile(envFile string, privateKeyHex string) error {
	privateKeyHex = strings.TrimSpace(strings.Trim(privateKeyHex, `"'`))
	if privateKeyHex == "" {
		return ErrInvalidPrivateKey
	}

	keyVar := PrivateKeyVarForEnvFile(envFile)
	keysFile := filepath.Join(filepath.Dir(envFile), ".env.keys")
	line := keyVar + `="` + escapeDoubleQuotes(privateKeyHex) + `"`

	raw, err := os.ReadFile(keysFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(keysFile, []byte(line+"\n"), 0o600)
	}

	content := string(raw)
	useCRLF := strings.Contains(content, "\r\n")
	norm := strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(norm, "\n")
	re := regexp.MustCompile(`^\s*` + regexp.QuoteMeta(keyVar) + `\s*=`)
	found := false
	for i, ln := range lines {
		if re.MatchString(ln) {
			lines[i] = line
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, line)
	}
	out := strings.Join(lines, "\n")
	if len(out) > 0 && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if useCRLF {
		out = strings.ReplaceAll(out, "\n", "\r\n")
	}
	return os.WriteFile(keysFile, []byte(out), 0o600)
}
