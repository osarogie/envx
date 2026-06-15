package envx

import (
	"strings"
	"testing"
)

func TestEncryptPreservingLayout_commentsAndBlanks(t *testing.T) {
	input := "# App secrets\n\nFOO=plain\n# tail comment\n"
	final := map[string]string{
		"FOO": "encrypted_pqc:AAA",
	}
	out, err := encryptPreservingLayout(input, final, ".env")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "# App secrets\n\n") {
		t.Fatalf("expected header preserved, got %q", out)
	}
	if !strings.Contains(out, `FOO="encrypted_pqc:AAA"`) {
		t.Fatalf("expected encrypted value, got %q", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "# tail comment") {
		t.Fatalf("expected tail comment preserved, got %q", out)
	}
}

func TestEncryptPreservingLayout_trailingCommentOnAssignment(t *testing.T) {
	input := "FOO=bar # my note\n"
	final := map[string]string{"FOO": "encrypted_pqc:BBB"}
	out, err := encryptPreservingLayout(input, final, ".env")
	if err != nil {
		t.Fatal(err)
	}
	want := `FOO="encrypted_pqc:BBB" # my note` + "\n"
	if out != want {
		t.Fatalf("got %q want %q", out, want)
	}
}

func TestEncryptPreservingLayout_crlf(t *testing.T) {
	input := "# x\r\nFOO=a\r\n"
	final := map[string]string{"FOO": "enc"}
	out, err := encryptPreservingLayout(input, final, ".env")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "\r\n") {
		t.Fatalf("expected CRLF preserved: %q", out)
	}
}

func TestEncryptPreservingLayout_appendsPublicKey(t *testing.T) {
	input := "API=1\n"
	final := map[string]string{
		"API":               "1",
		"DOTENV_PUBLIC_KEY": "pubval",
	}
	out, err := encryptPreservingLayout(input, final, ".env")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, `DOTENV_PUBLIC_KEY="pubval"`) {
		t.Fatalf("want public key as first line: %q", out)
	}
}

func TestEncryptPreservingLayout_emptyFile(t *testing.T) {
	final := map[string]string{"DOTENV_PUBLIC_KEY": "pk", "K": "v"}
	out, err := encryptPreservingLayout("", final, ".env")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, `DOTENV_PUBLIC_KEY="pk"`) {
		t.Fatalf("want public key first: %q", out)
	}
	if !strings.Contains(out, `K="v"`) {
		t.Fatalf("unexpected: %q", out)
	}
}

func TestEncryptPreservingLayout_envSpecificPublicKeyOnTop(t *testing.T) {
	input := "# banner\n\nAPI=1\nDOTENV_PUBLIC_KEY_DEVELOPMENT=pk\nOTHER=2\n"
	final := map[string]string{
		"DOTENV_PUBLIC_KEY_DEVELOPMENT": "pk",
		"API":                           "1",
		"OTHER":                         "2",
	}
	out, err := encryptPreservingLayout(input, final, ".env.development")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "DOTENV_PUBLIC_KEY_DEVELOPMENT=") {
		t.Fatalf("want public key as first line, got:\n%s", out)
	}
	if !strings.Contains(out, "# banner") {
		t.Fatalf("expected header comment preserved below public key: %q", out)
	}
	// Unchanged values keep original formatting (here API=1 stays unquoted).
	if !strings.Contains(out, "API=1") || !strings.Contains(out, "OTHER=2") {
		t.Fatal(out)
	}
}

func TestStripAssignmentLineForKey(t *testing.T) {
	in := "A=1\nDOTENV_PUBLIC_KEY=x\nB=2\n"
	out := stripAssignmentLineForKey(in, "DOTENV_PUBLIC_KEY")
	if strings.Contains(out, "DOTENV_PUBLIC_KEY") {
		t.Fatal(out)
	}
	if !strings.Contains(out, "A=1") || !strings.Contains(out, "B=2") {
		t.Fatal(out)
	}
}
