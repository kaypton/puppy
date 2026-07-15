package dashboard

import (
	"os"
	"runtime"
	"time"
)

const timeRFC3339 = time.RFC3339

// Version is the dashboard API version, surfaced via the /system endpoint.
const Version = "v1"

// timeSinceSeconds returns the elapsed seconds since t, rounded to
// milliseconds.
func timeSinceSeconds(t time.Time) float64 {
	return time.Since(t).Seconds()
}

// pid returns the current process ID.
func pid() int {
	return os.Getpid()
}

// goVersion returns the Go runtime version string.
func goVersion() string {
	return runtime.Version()
}
