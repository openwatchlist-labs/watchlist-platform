// Package alertcase is the central case data model: Store, ExternalAlert
// ingestion, ScreeningLineage, and CandidateSummary records. It is the
// most widely depended-on package in the review/case cluster - imported
// directly by internal/alertcaseapi, internal/reviewconsoleapi,
// internal/assistanceapi, internal/reviewconsole, and
// internal/vendoradapter (which creates case records from ingested
// vendor alerts). Changes here have broad blast radius; check importers
// before altering exported types.
package alertcase
