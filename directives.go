package envx

import (
	"strings"
	"unicode"

	"github.com/joho/godotenv"
)

// parsePlainDirectiveKeys scans assignment lines for an inline comment containing
// "dotenvx:plain" or "dotenvx-plain" (case-insensitive). Those keys are left as
// plaintext by EncryptFile; already-encrypted values are decrypted when marked plain.
func parsePlainDirectiveKeys(content string) map[string]bool {
	out := make(map[string]bool)
	norm := strings.ReplaceAll(content, "\r\n", "\n")
	for _, line := range strings.Split(norm, "\n") {
		trimmed := strings.TrimLeftFunc(line, unicode.IsSpace)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		key, comment := assignmentKeyAndInlineComment(line)
		if key == "" || comment == "" {
			continue
		}
		if commentHasPlainDirective(comment) {
			out[key] = true
		}
	}
	return out
}

func assignmentKeyAndInlineComment(line string) (key string, comment string) {
	m, err := godotenv.Unmarshal(line + "\n")
	if err != nil || len(m) != 1 {
		return "", ""
	}
	for k := range m {
		key = k
		break
	}
	_, rest, ok := splitEnvLinePrefix(line, key)
	if !ok {
		return "", ""
	}
	consumed := consumeValueSpan(rest)
	if consumed < 0 {
		return "", ""
	}
	tail := strings.TrimLeftFunc(rest[consumed:], unicode.IsSpace)
	if tail == "" || tail[0] != '#' {
		return key, ""
	}
	return key, strings.TrimSpace(tail[1:])
}

func commentHasPlainDirective(comment string) bool {
	c := strings.ToLower(strings.TrimSpace(comment))
	return strings.Contains(c, "dotenvx:plain") || strings.Contains(c, "dotenvx-plain")
}
