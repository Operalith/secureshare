package buildinfo

import "testing"

func TestCurrentAndDisplayVersion(t *testing.T) {
	originalVersion, originalCommit, originalBuildDate := Version, Commit, BuildDate
	t.Cleanup(func() {
		Version, Commit, BuildDate = originalVersion, originalCommit, originalBuildDate
	})

	Version = "0.1.0"
	Commit = "abc1234"
	BuildDate = "2026-08-17T12:00:00Z"

	if got := DisplayVersion(); got != "v0.1.0" {
		t.Fatalf("DisplayVersion() = %q", got)
	}
	info := Current()
	if info.Version != "0.1.0" || info.Commit != "abc1234" || info.BuildDate != "2026-08-17T12:00:00Z" {
		t.Fatalf("Current() = %+v", info)
	}
}

func TestEmptyBuildMetadataIsSafe(t *testing.T) {
	originalVersion, originalCommit, originalBuildDate := Version, Commit, BuildDate
	t.Cleanup(func() {
		Version, Commit, BuildDate = originalVersion, originalCommit, originalBuildDate
	})

	Version, Commit, BuildDate = "", "", ""
	info := Current()
	if info.Version != "unknown" || info.Commit != "unknown" || info.BuildDate != "unknown" {
		t.Fatalf("Current() = %+v", info)
	}
}
