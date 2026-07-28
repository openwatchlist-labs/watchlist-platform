package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// StableElementID creates a deterministic identifier from immutable parsing context.
// The identifier intentionally excludes normalized values so normalization changes do
// not change the identity of the native source element.
func StableElementID(sourceRef string, definition MessageDefinition, messageID string, transactionIndex *int, nativePath string, occurrence int) string {
	tx := ""
	if transactionIndex != nil {
		tx = strconv.Itoa(*transactionIndex)
	}
	parts := []string{sourceRef, string(definition), messageID, tx, nativePath, strconv.Itoa(occurrence)}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return "elem_" + hex.EncodeToString(sum[:12])
}
