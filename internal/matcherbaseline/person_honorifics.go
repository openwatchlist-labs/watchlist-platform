package matcherbaseline

// personHonorificTokens is a set of courtesy titles and professional-style
// suffixes attached to a person's name that carry no identifying
// information about WHO the person is - only a social/professional
// convention about how they're addressed. Dropped entirely from both
// query and candidate tokens before scoring, the same way
// corporate_suffixes.go drops legal-entity-type designators (see that
// file's comment for the fuller rationale on drop-vs-canonicalize).
//
// Real motivating case (issue #32, combined-03-padding-plus-nickname):
// "MR BILL J EXAMPLETON ESQ" against catalog entry "William Exampleton" -
// after nickname folding (BILL -> WILLIAM, see nicknames.go), the
// remaining mismatch is entirely the honorific prefix/suffix padding
// diluting every token-averaged scoring feature, not any actual
// difference in who the name refers to.
//
// Deliberately EXCLUDED, on purpose, not by oversight: JR, SR, II, III,
// IV and their spelled-out forms (JUNIOR, SENIOR). Unlike a courtesy
// title, a generational suffix is sometimes the ONLY thing distinguishing
// a sanctioned individual from an unrelated family member sharing the
// same name - dropping them risks exactly the false-positive/false-
// negative confusion this project's own screening exists to avoid. No
// generational suffix appears in this repository's current fixtures, but
// that absence isn't a reason to include them; the risk is real-world
// and well documented in OFAC-style list conventions, not
// fixture-specific.
var personHonorificTokens = map[string]bool{
	"MR": true, "MRS": true, "MS": true, "MISS": true, "MX": true,
	"DR": true, "PROF": true, "PROFESSOR": true,
	"REV": true, "REVEREND": true,
	"HON": true, "HONORABLE": true,
	"SIR": true, "DAME": true, "LORD": true, "LADY": true,
	"ESQ": true, "ESQUIRE": true,
}

// isPersonHonorific reports whether t is a recognized honorific/courtesy
// token, to be dropped rather than scored.
func isPersonHonorific(t string) bool {
	return personHonorificTokens[t]
}
