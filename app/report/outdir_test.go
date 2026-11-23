//go:build !windows

package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

func outDirReport() *model.Report {
	return &model.Report{GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Tool: "deploy-witness", Hostname: "h"}
}

func TestWriteRefusesAPlantedLink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "out")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "report.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "summary.csv")); err != nil {
		t.Fatal(err)
	}

	if _, _, err := WriteJSONFile(dir, outDirReport()); err == nil {
		t.Error("report.json was written through a link")
	}
	if _, err := WriteDir(dir, outDirReport()); err == nil {
		t.Error("summary.csv was written through a link")
	}
	if got, _ := os.ReadFile(target); string(got) != "original" {
		t.Errorf("link target changed: %q", got)
	}
}

func TestOutDirMustBeARealPrivateDirectory(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteDir(link, outDirReport()); err == nil {
		t.Error("a symlinked directory was accepted")
	}

	shared := filepath.Join(base, "shared")
	if err := os.Mkdir(shared, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := CheckOutDir(shared); err == nil {
		t.Error("a world-writable directory was accepted")
	}
}

func TestGeneratedOutDirNeverReusesAnExistingEntry(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "audit-h-1")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	got, err := CreateOutDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got == dir || !strings.HasPrefix(got, dir+"-") {
		t.Errorf("CreateOutDir = %q, want a new directory beside %q", got, dir)
	}
	if _, err := WriteDir(got, outDirReport()); err != nil {
		t.Errorf("the fresh directory was refused: %v", err)
	}
}

func TestRewriteKeepsPrivateMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	if _, err := WriteDir(dir, outDirReport()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "summary.csv")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteDir(dir, outDirReport()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
}
