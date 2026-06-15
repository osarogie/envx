package envx

import (
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/joho/godotenv"
)

// encryptPreservingLayout replaces assignment values with final[key], keeping comments,
// blank lines, and relative line order (except the env-specific public key line is moved to
// the first line; any content that was above it stays below it, in order). envFile selects the public key var name.
func encryptPreservingLayout(content string, final map[string]string, envFile string) (string, error) {
	pubVar := PublicKeyVarForEnvFile(envFile)
	if content == "" {
		return buildFreshFile(final, false, pubVar), nil
	}

	useCRLF := strings.Contains(content, "\r\n")
	norm := strings.ReplaceAll(content, "\r\n", "\n")

	lines := strings.Split(norm, "\n")
	var b strings.Builder
	for i, line := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}

		trimmed := strings.TrimLeftFunc(line, unicode.IsSpace)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			b.WriteString(line)
			continue
		}

		newLine, handled := rewriteAssignmentLine(line, final)
		if !handled {
			b.WriteString(line)
			continue
		}
		b.WriteString(newLine)
	}

	result := b.String()

	if pub, ok := final[pubVar]; ok && !lineContainsKeyAssignment(result, pubVar) {
		if strings.TrimSpace(result) != "" {
			result = strings.TrimRight(result, "\n") + "\n" + formatQuotedLine(pubVar, pub) + "\n"
		} else {
			result = formatQuotedLine(pubVar, pub) + "\n"
		}
	}

	result = movePublicKeyLineToTop(result, pubVar)

	if useCRLF {
		result = strings.ReplaceAll(result, "\n", "\r\n")
	}
	return result, nil
}

// movePublicKeyLineToTop places the pubVar assignment as the first line of the file.
// Lines that appeared before it (including blank lines and full-line # comments) follow it in order.
func movePublicKeyLineToTop(content, pubVar string) string {
	if content == "" {
		return content
	}
	norm := strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(norm, "\n")
	re := regexp.MustCompile(`^\s*(?:export\s+)?` + regexp.QuoteMeta(pubVar) + `\s*[=:]`)
	pubIdx := -1
	var pubLine string
	for i, line := range lines {
		if re.MatchString(line) {
			pubIdx = i
			pubLine = line
			break
		}
	}
	if pubIdx < 0 {
		return content
	}
	out := make([]string, 0, len(lines))
	out = append(out, pubLine)
	out = append(out, lines[:pubIdx]...)
	out = append(out, lines[pubIdx+1:]...)
	return strings.Join(out, "\n")
}

func buildFreshFile(final map[string]string, useCRLF bool, pubVar string) string {
	keys := make([]string, 0, len(final))
	for k := range final {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	sep := "\n"
	if useCRLF {
		sep = "\r\n"
	}
	var b strings.Builder
	if pub, ok := final[pubVar]; ok {
		b.WriteString(formatQuotedLine(pubVar, pub))
		b.WriteString(sep)
	}
	for _, k := range keys {
		if k == pubVar {
			continue
		}
		b.WriteString(formatQuotedLine(k, final[k]))
		b.WriteString(sep)
	}
	return b.String()
}

func formatQuotedLine(k, v string) string {
	return k + `="` + escapeDoubleQuotes(v) + `"`
}

func formatQuotedValue(v string) string {
	return `"` + escapeDoubleQuotes(v) + `"`
}

func lineContainsKeyAssignment(body, key string) bool {
	re := regexp.MustCompile(`(?m)^\s*(?:export\s+)?` + regexp.QuoteMeta(key) + `\s*[=:]`)
	return re.MatchString(body)
}

func rewriteAssignmentLine(line string, final map[string]string) (string, bool) {
	m, err := godotenv.Unmarshal(line + "\n")
	if err != nil || len(m) != 1 {
		return "", false
	}
	var key, parsedVal string
	for k, v := range m {
		key, parsedVal = k, v
	}
	want, ok := final[key]
	if !ok {
		return line, true
	}
	if want == parsedVal {
		return line, true
	}

	prefix, rest, ok := splitEnvLinePrefix(line, key)
	if !ok {
		return "", false
	}
	consumed := consumeValueSpan(rest)
	if consumed < 0 {
		return "", false
	}
	newLine := prefix + formatQuotedValue(want) + rest[consumed:]
	return newLine, true
}

func splitEnvLinePrefix(line, key string) (prefix string, rest string, ok bool) {
	re := regexp.MustCompile(`^(\s*(?:export\s+)?)(` + regexp.QuoteMeta(key) + `)(\s*[=:]\s*)`)
	loc := re.FindStringSubmatchIndex(line)
	if loc == nil {
		return "", "", false
	}
	end := loc[1]
	return line[:end], line[end:], true
}

func consumeValueSpan(rest string) int {
	rest = strings.TrimLeftFunc(rest, unicode.IsSpace)
	if rest == "" {
		return 0
	}
	switch rest[0] {
	case '"':
		return consumeDoubleQuoted(rest)
	case '\'':
		return consumeSingleQuoted(rest)
	default:
		return consumeUnquoted(rest)
	}
}

func consumeDoubleQuoted(rest string) int {
	if len(rest) < 1 || rest[0] != '"' {
		return -1
	}
	i := 1
	for i < len(rest) {
		if rest[i] == '"' {
			if !isEscaped(rest, i) {
				return i + 1
			}
		}
		if rest[i] == '\n' {
			return -1
		}
		i++
	}
	return -1
}

func consumeSingleQuoted(rest string) int {
	if len(rest) < 1 || rest[0] != '\'' {
		return -1
	}
	i := 1
	for i < len(rest) {
		if rest[i] == '\'' {
			if !isEscaped(rest, i) {
				return i + 1
			}
		}
		if rest[i] == '\n' {
			return -1
		}
		i++
	}
	return -1
}

// isEscaped reports whether byte at idx is escaped by an odd number of preceding backslashes.
func isEscaped(s string, idx int) bool {
	bs := 0
	for j := idx - 1; j >= 0 && s[j] == '\\'; j-- {
		bs++
	}
	return bs%2 == 1
}

func consumeUnquoted(rest string) int {
	end := len(rest)
	for i := 0; i < len(rest); i++ {
		if rest[i] != '#' {
			continue
		}
		if i == 0 {
			continue
		}
		// Inline comments start at a '#' that is preceded by whitespace.
		// Preserve the exact whitespace/comment suffix by trimming the value span only.
		if unicode.IsSpace(rune(rest[i-1])) {
			j := i - 1
			for j >= 0 && unicode.IsSpace(rune(rest[j])) {
				j--
			}
			end = j + 1
			break
		}
	}
	return len(strings.TrimRightFunc(rest[:end], unicode.IsSpace))
}
