package scripts_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCodesignReleaseBinarySkipsCredentialFreeBuilds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("codesign-release-binary.sh is a POSIX shell script")
	}

	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}

	scriptDir := signingScriptDir(t)
	cmd := exec.CommandContext(t.Context(), bash, "./codesign-release-binary.sh", "darwin_arm64", "/does/not/exist")
	cmd.Dir = scriptDir
	cmd.Env = signingTestEnv("DISCRAWL_CODESIGN_REQUIRED=0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("credential-free signing hook failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "skipping Developer ID signing") {
		t.Fatalf("missing snapshot skip notice: %s", output)
	}
}

func TestCodesignReleaseBinaryFailsClosedForOfficialBuilds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("codesign-release-binary.sh is a POSIX shell script")
	}

	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}

	scriptDir := signingScriptDir(t)
	cmd := exec.CommandContext(t.Context(), bash, "./codesign-release-binary.sh", "darwin_arm64", "/does/not/exist")
	cmd.Dir = scriptDir
	cmd.Env = signingTestEnv("DISCRAWL_CODESIGN_REQUIRED=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("official signing hook unexpectedly succeeded: %s", output)
	}
	want := "CODESIGN_IDENTITY is required"
	if runtime.GOOS != "darwin" {
		want = "official macOS release signing must run on macOS"
	}
	if !strings.Contains(string(output), want) {
		t.Fatalf("unexpected official signing failure: %s", output)
	}
}

func TestVerifyMacOSReleaseAcceptsGoReleaserArchive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("verify-macos-release.sh is a POSIX shell script")
	}

	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	tar, err := exec.LookPath("tar")
	if err != nil {
		t.Skip("tar is not available")
	}
	if _, err := exec.LookPath("shasum"); err != nil {
		t.Skip("shasum is not available")
	}

	tempDir := t.TempDir()
	payloadDir := filepath.Join(tempDir, "payload")
	if err := os.Mkdir(payloadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"CHANGELOG.md", "LICENSE", "README.md"} {
		if err := os.WriteFile(filepath.Join(payloadDir, name), []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutable(t, filepath.Join(payloadDir, "discrawl"), "#!/bin/sh\n[ \"$1\" = --version ]\nprintf '0.11.5\\n'\n")

	archive := filepath.Join(tempDir, "discrawl_0.11.5_darwin_arm64.tar.gz")
	tarCmd := exec.CommandContext(t.Context(), tar, "-czf", archive, "-C", payloadDir, "CHANGELOG.md", "LICENSE", "README.md", "discrawl")
	if output, err := tarCmd.CombinedOutput(); err != nil {
		t.Fatalf("create archive: %v\n%s", err, output)
	}
	archiveBytes, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	checksums := filepath.Join(tempDir, "checksums.txt")
	checksumLine := fmt.Sprintf("%x  %s\n", sha256.Sum256(archiveBytes), filepath.Base(archive))
	if err := os.WriteFile(checksums, []byte(checksumLine), 0o644); err != nil {
		t.Fatal(err)
	}

	stubDir := filepath.Join(tempDir, "bin")
	if err := os.Mkdir(stubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(stubDir, "uname"), "#!/bin/sh\nprintf 'Darwin\\n'\n")
	writeExecutable(t, filepath.Join(stubDir, "codesign"), "#!/bin/sh\nprintf 'Identifier=org.openclaw.discrawl\\nTeamIdentifier=FWJYW4S8P8\\nAuthority=Developer ID Application: OpenClaw Foundation (FWJYW4S8P8)\\n' >&2\n")
	writeExecutable(t, filepath.Join(stubDir, "lipo"), "#!/bin/sh\nprintf 'arm64\\n'\n")

	scriptDir := signingScriptDir(t)
	cmd := exec.CommandContext(t.Context(), bash, "./verify-macos-release.sh", "v0.11.5", archive, checksums)
	cmd.Dir = scriptDir
	cmd.Env = append(os.Environ(), "PATH="+stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify GoReleaser archive: %v\n%s", err, output)
	}
}

func signingScriptDir(t *testing.T) string {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate test file")
	}
	return filepath.Dir(testFile)
}

func signingTestEnv(extra string) []string {
	env := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "CODESIGN_IDENTITY=") || strings.HasPrefix(entry, "DISCRAWL_CODESIGN_REQUIRED=") {
			continue
		}
		env = append(env, entry)
	}
	return append(env, extra)
}

func writeExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatal(err)
	}
}
