package buildinfo

import "strings"

// These values are the single source of truth for the application release.
// Commit and BuildDate may be replaced with -ldflags at build time.
var (
	Version   = "0.1.0"
	Commit    = "unknown"
	BuildDate = "unknown"
)

type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
}

func Current() Info {
	return Info{
		Version:   normalized(Version),
		Commit:    normalized(Commit),
		BuildDate: normalized(BuildDate),
	}
}

func DisplayVersion() string {
	value := normalized(Version)
	if strings.HasPrefix(value, "v") {
		return value
	}
	return "v" + value
}

func normalized(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return value
}
