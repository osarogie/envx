package envx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListKeys(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, ".env")
	contents := "# comment\nPLAINVAL=hello\nSECRET=encrypted_pqc:AAA\nEMPTY=\n"
	if err := os.WriteFile(file, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	infos, err := ListKeys(file)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}

	// Sorted: EMPTY, PLAINVAL, SECRET
	want := []KeyInfo{
		{Key: "EMPTY", Encrypted: false},
		{Key: "PLAINVAL", Encrypted: false},
		{Key: "SECRET", Encrypted: true},
	}
	if len(infos) != len(want) {
		t.Fatalf("got %d keys, want %d: %+v", len(infos), len(want), infos)
	}
	for i, w := range want {
		if infos[i] != w {
			t.Errorf("index %d: got %+v, want %+v", i, infos[i], w)
		}
	}
}

func TestListKeysMissingFile(t *testing.T) {
	infos, err := ListKeys(filepath.Join(t.TempDir(), "nope.env"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(infos) != 0 {
		t.Fatalf("missing file should yield no keys, got %+v", infos)
	}
}
