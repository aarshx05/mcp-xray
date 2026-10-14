package reposcan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Symlinks that cannot be read as files -- one to a directory, one to
// itself -- are skipped, and the rest of the repository is still scanned.
func TestSecretsScanner_SkipsUnreadableSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs extra privileges on Windows")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Split so this file is not itself reported as containing a token.
	token := "gh" + "p_" + "8sR2kQ9vLx4TzW7nB1mYc5pD3fH6jE0aK2uV"
	if err := os.WriteFile(filepath.Join(root, "config.py"), []byte("GITHUB_TOKEN = \""+token+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(root, "linked-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loop", filepath.Join(root, "loop")); err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.Root = root

	findings, err := NewSecretsScanner(root, config).Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("findings = %d, want the one token in config.py", len(findings))
	}
}

func TestSecretsScanner_UnreadableRootFails(t *testing.T) {
	config := DefaultConfig()
	if _, err := NewSecretsScanner(filepath.Join(t.TempDir(), "missing"), config).Scan(context.Background()); err == nil {
		t.Error("scanning a missing root must fail rather than report no secrets")
	}
}
