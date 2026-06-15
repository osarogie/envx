package envx

import (
	"regexp"
	"strings"
)

// stripAssignmentLineForKey removes full assignment lines for the given env var name.
func stripAssignmentLineForKey(s, key string) string {
	if s == "" {
		return s
	}
	useCRLF := strings.Contains(s, "\r\n")
	norm := strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(norm, "\n")
	re := regexp.MustCompile(`^\s*(?:export\s+)?` + regexp.QuoteMeta(key) + `\s*[=:]`)
	out := lines[:0]
	for _, line := range lines {
		if re.MatchString(line) {
			continue
		}
		out = append(out, line)
	}
	res := strings.Join(out, "\n")
	if useCRLF {
		res = strings.ReplaceAll(res, "\n", "\r\n")
	}
	return res
}
