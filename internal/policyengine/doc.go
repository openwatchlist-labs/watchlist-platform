// Package policyengine evaluates a false-positive ClassificationBatch
// (internal/falsepositive) against a versioned, checksummed policy
// document and produces a disposition for each item: clear, investigate,
// or escalate. Policy documents are YAML, strictly validated, and
// checksum-gated - a policy that fails its own checksum check is
// rejected rather than silently applied (see validate.go and
// decision_validate.go, and their tests, for the deliberate negative-path
// coverage of this).
//
// cmd/policy-evaluate is the CLI entrypoint; see its own tests
// (cmd/policy-evaluate/main_test.go) for a real, runnable end-to-end
// example against this repo's default policy
// (configs/policies/transaction-screening-r1.yaml).
package policyengine
