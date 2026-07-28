# Synthetic OFAC Advanced XML fixture

This parser regression fixture models the important OFAC Advanced XML version 3 cross-reference structure without containing any real sanctions-list subject. It covers reference value dictionaries, Latin and Cyrillic name parts, weak aliases, locations, identity/registration documents, features, profile relationships, sanctions entries, program measures, and legal-authority events.

The fixture follows the XSD element and attribute names exercised by the parser, including `LocPartTypeID`, `LocationPartValue`, `IDRegDocTypeID`, `IdentityID`, `IDRegDocDateTypeID`, `ListID`, `ProfileID`, and `SanctionsEntryID`. Focused tests extend it with multiple profiles, multiple identities, multiple sanctions entries, and mixed SDN/non-SDN list memberships.

It is intentionally compact and is not presented as a complete standalone XSD-validation corpus: the official XSD contains many additional required reference-value collections and attributes that are unrelated to the parser behaviors under test.
