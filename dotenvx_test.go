package envx

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEnvironWithMergedOverlay_respectsBaseWhenNotOverload(t *testing.T) {
	base := []string{"PATH=/bin", "DOTENV_PRIVATE_KEY=secret", "DOTENV_PRIVATE_KEY_PRODUCTION=x", "OTHER=1", "REDIS_URL=from-runtime"}
	merged := map[string]string{
		"DATABASE_URL":        "fromfile",
		"REDIS_URL":           "from-file",
		"DOTENV_PRIVATE_KEY":  "should-not-apply",
		"DOTENV_PUBLIC_KEY":   "pub",
		"SECRET_SHOULD_APPLY": "y",
	}
	got := EnvironWithMergedOverlay(base, merged, false)
	gotMap := map[string]string{}
	for _, kv := range got {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("bad kv %q", kv)
		}
		gotMap[k] = v
	}
	if _, ok := gotMap["DOTENV_PRIVATE_KEY"]; ok {
		t.Fatal("private key should be stripped from child env")
	}
	if _, ok := gotMap["DOTENV_PRIVATE_KEY_PRODUCTION"]; ok {
		t.Fatal("private key suffix should be stripped")
	}
	if gotMap["DATABASE_URL"] != "fromfile" || gotMap["SECRET_SHOULD_APPLY"] != "y" || gotMap["PATH"] != "/bin" {
		t.Fatalf("got %#v", gotMap)
	}
	// Orchestrator-set REDIS_URL must survive when overload is false — the bug this fixes:
	// without it, .env.development's REDIS_URL silently replaces compose/kamal's value and
	// workers + asynqmon land on different Redis instances.
	if gotMap["REDIS_URL"] != "from-runtime" {
		t.Fatalf("expected base REDIS_URL to win, got %q", gotMap["REDIS_URL"])
	}
}

func TestEnvironWithMergedOverlay_overloadReplacesBase(t *testing.T) {
	base := []string{"PATH=/bin", "REDIS_URL=from-runtime", "OTHER=1"}
	merged := map[string]string{
		"REDIS_URL":           "from-file",
		"SECRET_SHOULD_APPLY": "y",
	}
	got := EnvironWithMergedOverlay(base, merged, true)
	gotMap := map[string]string{}
	for _, kv := range got {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("bad kv %q", kv)
		}
		gotMap[k] = v
	}
	if gotMap["REDIS_URL"] != "from-file" {
		t.Fatalf("overload should let merged win, got %q", gotMap["REDIS_URL"])
	}
	if gotMap["SECRET_SHOULD_APPLY"] != "y" || gotMap["PATH"] != "/bin" {
		t.Fatalf("got %#v", gotMap)
	}
}

func TestEnvironMergedKeys_respectsBaseWhenNotOverload(t *testing.T) {
	base := []string{"PATH=/bin", "DATABASE_URL=from-runtime", "OTHER=1"}
	merged := map[string]string{
		"DATABASE_URL":            "from-file",
		"MIGRATION_DATABASE_URL":  "mdev",
		"SECRET_SHOULD_NOT_APPLY": "x",
	}
	got := EnvironMergedKeys(base, merged, []string{"DATABASE_URL", "MIGRATION_DATABASE_URL"}, false)
	want := map[string]string{
		"PATH": "/bin", "DATABASE_URL": "from-runtime", "MIGRATION_DATABASE_URL": "mdev", "OTHER": "1",
	}
	gotMap := map[string]string{}
	for _, kv := range got {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("bad kv %q", kv)
		}
		gotMap[k] = v
	}
	if !reflect.DeepEqual(gotMap, want) {
		t.Fatalf("got %#v want %#v", gotMap, want)
	}
}

func TestEnvironMergedKeys_overloadReplacesBase(t *testing.T) {
	base := []string{"PATH=/bin", "DATABASE_URL=old", "OTHER=1"}
	merged := map[string]string{
		"DATABASE_URL":            "new",
		"MIGRATION_DATABASE_URL":  "mdev",
		"SECRET_SHOULD_NOT_APPLY": "x",
	}
	got := EnvironMergedKeys(base, merged, []string{"DATABASE_URL", "MIGRATION_DATABASE_URL"}, true)
	want := map[string]string{
		"PATH": "/bin", "DATABASE_URL": "new", "MIGRATION_DATABASE_URL": "mdev", "OTHER": "1",
	}
	gotMap := map[string]string{}
	for _, kv := range got {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("bad kv %q", kv)
		}
		gotMap[k] = v
	}
	if !reflect.DeepEqual(gotMap, want) {
		t.Fatalf("got %#v want %#v", gotMap, want)
	}
}

func TestFilesFromPrivateKeys(t *testing.T) {
	env := []string{
		"DOTENV_PRIVATE_KEY=abc",
		"DOTENV_PRIVATE_KEY_PRODUCTION=def",
		"DOTENV_PRIVATE_KEY_CI_LOCAL=ghi",
	}

	got := FilesFromPrivateKeys(env)
	want := []string{".env", ".env.ci.local", ".env.production"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v; want %v", got, want)
	}
}

func TestFilesFromPrivateKeys_ignoresEmptyKeyPlaceholders(t *testing.T) {
	env := []string{
		"DOTENV_PRIVATE_KEY=",
		"DOTENV_PRIVATE_KEY_PRODUCTION=real-key-material",
	}
	got := FilesFromPrivateKeys(env)
	want := []string{".env.production"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v; want %v", got, want)
	}
}

func TestDiscoverEnvFilesWithPrivateKeysInEnv(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if got := DiscoverEnvFilesWithPrivateKeysInEnv(); len(got) != 0 {
		t.Fatalf("no files and no keys: got %v", got)
	}

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.production"), []byte("B=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.keys"), []byte("IGNORED=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("DOTENV_PRIVATE_KEY", `"secret"`)
	t.Setenv("DOTENV_PRIVATE_KEY_PRODUCTION", `"other"`)

	got := DiscoverEnvFilesWithPrivateKeysInEnv()
	want := []string{filepath.Join(dir, ".env"), filepath.Join(dir, ".env.production")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}

	t.Setenv("DOTENV_PRIVATE_KEY_PRODUCTION", "")
	got2 := DiscoverEnvFilesWithPrivateKeysInEnv()
	want2 := []string{filepath.Join(dir, ".env")}
	if !reflect.DeepEqual(got2, want2) {
		t.Fatalf("got %#v want %#v", got2, want2)
	}
}

func TestLoad_unsetsPrivateKeysFromEnv(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("EPHEMERAL_UNSET_TEST=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOTENV_PRIVATE_KEY", "opaque-material-not-in-git")
	t.Setenv("DOTENV_PRIVATE_KEY_PRODUCTION", "another-key")

	if _, err := Load(nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv("DOTENV_PRIVATE_KEY"); ok {
		t.Fatal("DOTENV_PRIVATE_KEY should be unset after Load")
	}
	if _, ok := os.LookupEnv("DOTENV_PRIVATE_KEY_PRODUCTION"); ok {
		t.Fatal("DOTENV_PRIVATE_KEY_PRODUCTION should be unset after Load")
	}
}

func TestLoad_nilOptsUsesDiscovery(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("DISCOVERY_LOAD_TEST=fromdisc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOTENV_PRIVATE_KEY", "k")

	m, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if m["DISCOVERY_LOAD_TEST"] != "fromdisc" {
		t.Fatalf("DISCOVERY_LOAD_TEST=%q", m["DISCOVERY_LOAD_TEST"])
	}
	if os.Getenv("DISCOVERY_LOAD_TEST") != "fromdisc" {
		t.Fatalf("env DISCOVERY_LOAD_TEST=%q", os.Getenv("DISCOVERY_LOAD_TEST"))
	}
}

func TestLoad_MergeAndOverload(t *testing.T) {
	dir := t.TempDir()

	f1 := filepath.Join(dir, ".env")
	f2 := filepath.Join(dir, ".env.override")

	if err := os.WriteFile(f1, []byte("A=1\nB=from1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("B=from2\nC=3\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("B", "preexisting")

	if _, err := Load(&LoadOptions{Files: []string{f1, f2}, Overload: false}); err != nil {
		t.Fatal(err)
	}

	if got := os.Getenv("A"); got != "1" {
		t.Fatalf("A=%q", got)
	}
	// no overload => keep preexisting env
	if got := os.Getenv("B"); got != "preexisting" {
		t.Fatalf("B=%q", got)
	}
	if got := os.Getenv("C"); got != "3" {
		t.Fatalf("C=%q", got)
	}

	if _, err := Load(&LoadOptions{Files: []string{f1, f2}, Overload: true}); err != nil {
		t.Fatal(err)
	}
	// overload => apply merged value (file2 wins)
	if got := os.Getenv("B"); got != "from2" {
		t.Fatalf("B=%q", got)
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	ctx := EncryptionContext{VarName: "GREETING", PublicKeyVar: "DOTENV_PUBLIC_KEY"}

	enc, err := Encrypt("hello", pub, ctx)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := DecryptIfEncrypted(enc, []string{priv}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if dec != "hello" {
		t.Fatalf("got %q", dec)
	}
}

func TestLoad_DecryptsEncryptedValuesUsingEnvKeysFile(t *testing.T) {
	dir := t.TempDir()

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	// Bind to the same context Load will reconstruct for HELLO in a base .env file.
	enc, err := Encrypt("World", pub, EncryptionContext{VarName: "HELLO", PublicKeyVar: "DOTENV_PUBLIC_KEY"})
	if err != nil {
		t.Fatal(err)
	}

	envPath := filepath.Join(dir, ".env")
	keysPath := filepath.Join(dir, ".env.keys")

	if err := os.WriteFile(envPath, []byte("DOTENV_PUBLIC_KEY="+quote(pub)+"\nHELLO="+quote(enc)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysPath, []byte("DOTENV_PRIVATE_KEY="+quote(priv)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	values, err := Load(&LoadOptions{Files: []string{envPath}, Overload: true})
	if err != nil {
		t.Fatal(err)
	}
	if values["HELLO"] != "World" {
		t.Fatalf("HELLO=%q", values["HELLO"])
	}
}

func quote(s string) string {
	return `"` + s + `"`
}
