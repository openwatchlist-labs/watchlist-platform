// Package matchercontext layers jurisdiction, address, and contextual-
// phrase evidence on top of internal/matcherbaseline's name-similarity
// scoring - e.g. weighing whether a candidate's known jurisdiction is
// consistent with the payment/case context, not just whether the name
// matches. Built on matcherbaseline, not a replacement for it.
package matchercontext
