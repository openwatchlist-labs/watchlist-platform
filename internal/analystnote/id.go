package analystnote

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func checksumJSON(value any) string {
	data, _ := json.Marshal(value)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func hashJSON(prefix string, value any) string {
	data, _ := json.Marshal(value)
	digest := sha256.Sum256(data)
	return prefix + hex.EncodeToString(digest[:12])
}

func ProfileChecksum(profile Profile) string {
	profile.ProfileChecksum = ""
	return checksumJSON(profile)
}

func stableClaimID(claim Claim) string {
	copy := claim
	copy.ClaimID = ""
	return hashJSON("analyst_claim_", copy)
}

func stableNoteID(note Note) string {
	copy := note
	copy.NoteID = ""
	return hashJSON("analyst_note_", copy)
}

func stableInvocationID(invocation Invocation) string {
	copy := invocation
	copy.InvocationID = ""
	return hashJSON("analyst_invocation_", copy)
}
