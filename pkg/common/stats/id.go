package stats

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync/atomic"
)

// idCounter is a process-wide monotonic counter used as a prefix for
// connection IDs. Combined with random bytes, this gives IDs that are unique
// across restarts and concurrent goroutines without external dependencies.
var idCounter atomic.Uint64

// GenerateConnectionID returns a short, unique connection identifier suitable
// for use as ConnectionInfo.ID. The format is "conn-<counter>-<randhex>".
func GenerateConnectionID() string {
	n := idCounter.Add(1)
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return "conn-" + hex.EncodeToString(buf[:]) + "-" + strconv.FormatUint(n, 36)
}
