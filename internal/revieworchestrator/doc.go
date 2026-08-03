// Package revieworchestrator coordinates the human review workflow on
// top of a policy disposition (internal/policyengine) and false-positive
// classification (internal/falsepositive): four-eyes controls,
// escalation routing, and RAG-assisted analyst context (internal/rag,
// internal/analystnote). It also imports internal/matcherprovider
// directly, separately from internal/matcherbaseline's own use via
// cmd/matcher-run - check current imports before assuming which matching
// path is in play here if extending this package.
package revieworchestrator
