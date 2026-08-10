package matcherbaseline

// nicknameToCanonical maps common English given-name nicknames/diminutives
// to one dominant canonical (full/formal) form. Applied per-token during
// tokens() (see normalize.go), symmetrically to both the query and every
// candidate name - so two entries that already agree (both "Bill", or both
// "William") still match each other exactly, and this only helps the
// cross-variant case (one side "Bill", the other "William").
//
// Deliberately scoped, not exhaustive:
//
//   - English-language nicknames only. Nickname/diminutive conventions in
//     other languages are a real, separate gap - not attempted here.
//   - Genuinely AMBIGUOUS nicknames are deliberately EXCLUDED rather than
//     guessed at. For example "Pat" is a common nickname for both Patrick
//     and Patricia, "Chris" for both Christopher and Christina/Christine,
//     "Sam" for both Samuel and Samantha. Picking one canonical form for an
//     ambiguous nickname would help the case that matches the guess and
//     actively hurt the other - e.g. defaulting "Pat" to "Patrick" would
//     canonicalize an actual "Pat Smith" (Patricia) query away from a
//     catalog entry correctly on file as "Patricia Smith", which is worse
//     than not canonicalizing at all. Only nicknames with one clearly
//     dominant full form are included.
//   - A one-to-one mapping, not one-to-many. Supporting multiple candidate
//     expansions per ambiguous nickname (trying each and keeping the best
//     score) would be a reasonable further extension, but is more invasive
//     than this change and is left as future work if the excluded
//     ambiguous names turn out to matter in practice.
var nicknameToCanonical = map[string]string{
	"BILL": "WILLIAM", "WILL": "WILLIAM", "BILLY": "WILLIAM", "WILLY": "WILLIAM",
	"BOB": "ROBERT", "BOBBY": "ROBERT", "ROB": "ROBERT", "ROBBIE": "ROBERT",
	"DICK": "RICHARD", "RICK": "RICHARD", "RICKY": "RICHARD", "RICHIE": "RICHARD",
	"JIM": "JAMES", "JIMMY": "JAMES",
	"JACK": "JOHN", "JOHNNY": "JOHN",
	"TOM": "THOMAS", "TOMMY": "THOMAS",
	"MIKE": "MICHAEL", "MICKEY": "MICHAEL", "MIKEY": "MICHAEL",
	"DAVE": "DAVID", "DAVEY": "DAVID",
	"CHUCK": "CHARLES", "CHARLIE": "CHARLES",
	"ED": "EDWARD", "EDDIE": "EDWARD", "TED": "EDWARD", "TEDDY": "EDWARD",
	"TONY": "ANTHONY",
	"ANDY": "ANDREW", "DREW": "ANDREW",
	"GREG": "GREGORY",
	"KEN":  "KENNETH", "KENNY": "KENNETH",
	"LARRY": "LAWRENCE",
	"JOE":   "JOSEPH", "JOEY": "JOSEPH",
	"PETE": "PETER",
	"MATT": "MATTHEW",
	"DAN":  "DANIEL", "DANNY": "DANIEL",
	"NICK": "NICHOLAS", "NICKY": "NICHOLAS",
	"ALEX": "ALEXANDER",
	"BEN":  "BENJAMIN", "BENNY": "BENJAMIN",
	"HANK":  "HENRY",
	"HARRY": "HAROLD",
	"RON":   "RONALD", "RONNIE": "RONALD",
	"STAN": "STANLEY",
	"WALT": "WALTER",

	"LIZ": "ELIZABETH", "BETH": "ELIZABETH", "LIZZY": "ELIZABETH", "ELIZA": "ELIZABETH", "BETSY": "ELIZABETH",
	"PEGGY": "MARGARET", "MEG": "MARGARET", "MAGGIE": "MARGARET", "MARGE": "MARGARET",
	"KATE": "KATHERINE", "KATIE": "KATHERINE", "KATHY": "KATHERINE",
	"SUE": "SUSAN", "SUZY": "SUSAN", "SUZANNE": "SUSAN",
	"JEN": "JENNIFER", "JENNY": "JENNIFER",
	"PATTY": "PATRICIA", "TRISH": "PATRICIA", "TRICIA": "PATRICIA",
	"DEB": "DEBORAH", "DEBBIE": "DEBORAH",
	"CINDY": "CYNTHIA",
	"BARB":  "BARBARA", "BARBIE": "BARBARA",
	"CARRIE": "CAROLINE",
	"GINNY":  "VIRGINIA",
	"JOSIE":  "JOSEPHINE",
	"PENNY":  "PENELOPE",
	"SANDY":  "SANDRA",
	"VICKY":  "VICTORIA",
	"WENDY":  "GWENDOLYN",
}

// canonicalizeToken returns the nickname's canonical full form if t is a
// recognized, unambiguous English diminutive; otherwise it returns t
// unchanged.
func canonicalizeToken(t string) string {
	if canonical, ok := nicknameToCanonical[t]; ok {
		return canonical
	}
	return canonicalizeTransliterationVariant(t)
}
