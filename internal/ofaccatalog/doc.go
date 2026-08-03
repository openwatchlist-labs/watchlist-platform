// Package ofaccatalog defines the strict "direct-list" catalog contract:
// Catalog and Record types, deterministic checksum computation
// (Checksum), and header validation (ValidateCatalog) that is
// intentionally rigid - catalog_id must be exactly "ofac-sdn-direct",
// provider_record_id must be exactly "ofac:sdn:<uid>",
// source_assertion.source_id must be exactly "ofac-sls", list_id must be
// exactly "SDN" - even for synthetic test data (see
// cmd/adversarial-checksum-fix for a worked example of satisfying this
// for a hand-authored catalog).
//
// LoadFromFile is what internal/ofacruntime's compiler and
// cmd/ofac-runtime consume; internal/ofacsource validates the
// acquisition manifest this catalog's source_manifest field must satisfy.
package ofaccatalog
