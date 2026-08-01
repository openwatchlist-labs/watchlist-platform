package matcherbaseline

// corporateSuffixTokens is a set of strict legal-entity-type designators -
// tokens that indicate WHAT KIND of legal entity something is (a limited
// company, a GmbH, an incorporated entity), not tokens that describe WHAT
// the entity does or is called. Dropped entirely from both query and
// candidate tokens before scoring (see tokens() in normalize.go).
//
// Why drop rather than canonicalize to one form (contrast with
// nicknames.go, which canonicalizes to a single dominant form): there is
// no single "canonical" legal-entity suffix the way WILLIAM is canonical
// relative to BILL. GMBH, LTD, LLC, and INC are all equally valid, just
// different jurisdictions/legal regimes for what is otherwise the same
// underlying business concept. Picking one as canonical would be
// arbitrary; dropping all of them symmetrically means a query using any
// suffix (or none) is compared purely on the substantive part of the
// name, which is the actual point of issue #11 - re-incorporating the
// same operation under a different corporate wrapper is a real,
// documented sanctions-evasion pattern, not just messy data.
//
// Accepted trade-off, stated plainly: two GENUINELY DIFFERENT entities
// that happen to share a name and differ ONLY by legal-entity suffix
// (e.g. an unrelated "Acme Ltd" in the UK and "Acme GmbH" in Germany)
// become indistinguishable by suffix alone under this matcher. That's
// the same category of trade-off already accepted for token reordering
// (#8) and nicknames (#10): the suffix wasn't a reliable signal to begin
// with, since it's this same list that made "Orion Trading LTD" fail to
// match "Orion Trading GmbH" in the first place.
//
// Deliberately NOT included: generic business-descriptor words like
// HOLDINGS, TRADING, GROUP, INTERNATIONAL, PARTNERS. Those describe what
// the entity does or how it's organized and are a real, meaningful part
// of the name - e.g. "Orion Holdings GmbH" and "Orion Trading GmbH" are
// two different entities in this repository's own fixtures, used
// specifically to test that near-duplicate names still get surfaced for
// human disambiguation rather than silently merged (see
// obfuscation-09-near-duplicate-disambiguation in the adversarial test
// bank). Dropping GMBH from both doesn't affect that distinction, since
// both share the same suffix already; dropping HOLDINGS/TRADING as if
// they were suffixes would have destroyed it.
var corporateSuffixTokens = map[string]bool{
	"LLC": true, "LLP": true, "LP": true,
	"LTD": true, "LIMITED": true,
	"INC": true, "INCORPORATED": true,
	"CORP": true, "CORPORATION": true,
	"CO": true, "COMPANY": true,
	"GMBH": true, "AG": true, "KG": true, "GBR": true,
	"SA": true, "SAS": true, "SARL": true, "SL": true, "SPA": true, "SRL": true,
	"NV": true, "BV": true,
	"PLC": true,
	"PTY": true,
	"OY":  true, "AB": true, "AS": true, "ASA": true,
}

// isCorporateSuffix reports whether t is a recognized legal-entity-type
// suffix token, to be dropped rather than scored.
func isCorporateSuffix(t string) bool {
	return corporateSuffixTokens[t]
}
