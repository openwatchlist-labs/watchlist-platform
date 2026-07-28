package rag

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func hashJSON(prefix string, value any) string {
	data, _ := json.Marshal(value)
	digest := sha256.Sum256(data)
	return prefix + hex.EncodeToString(digest[:12])
}

func checksumJSON(value any) string {
	data, _ := json.Marshal(value)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func ManifestChecksum(manifest CorpusManifest) string {
	manifest.CorpusChecksum = ""
	return checksumJSON(manifest)
}

func PolicyChecksum(policy RetrievalPolicy) string {
	policy.PolicyChecksum = ""
	return checksumJSON(policy)
}

func stableSnapshotID(snapshot CorpusSnapshot) string {
	copy := snapshot
	copy.SnapshotID = ""
	return hashJSON("rag_snapshot_", copy)
}

func stableQueryID(query RetrievalQuery) string {
	copy := query
	copy.QueryID = ""
	return hashJSON("rag_query_", copy)
}

func stableCitationID(citation Citation) string {
	copy := citation
	copy.CitationID = ""
	return hashJSON("citation_", copy)
}

func stableCitationPackageID(pkg CitationPackage) string {
	copy := pkg
	copy.CitationPackageID = ""
	return hashJSON("citation_package_", copy)
}
