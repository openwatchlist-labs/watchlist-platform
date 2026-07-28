package ofacadvanced

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

var ErrInvalidXML = errors.New("invalid OFAC SDN Advanced XML")

type xmlNode struct {
	Name     string
	Attrs    map[string]string
	Text     string
	Children []*xmlNode
}

type refSets struct {
	sets map[string]map[string]string
}

type parsedDocument struct {
	Namespace                 string
	Version                   string
	SchemaLocation            string
	DateOfIssue               string
	Refs                      refSets
	Locations                 map[string]Address
	Documents                 map[string]Identifier
	PartyCandidates           []partyCandidate
	Parties                   []Party
	Relationships             []Relationship
	Sanctions                 map[string][]sanctionData
	SelectedSanctionsEntryIDs map[string]struct{}
	Stats                     SourceStats
}

type partyCandidate struct {
	UID      int
	Remarks  string
	Profiles []Party
}

type sanctionData struct {
	SourceEntryID    string
	ProfileID        string
	ListID           string
	Programs         []string
	LegalAuthorities []LegalAuthority
	List             string
}

func Parse(a Acquired) (Result, error) {
	doc, err := parseDocument(a.Bytes)
	if err != nil {
		return Result{}, err
	}
	manifest := ofacsource.SourceManifest{
		SchemaVersion:       ofacsource.ManifestSchemaVersion,
		Authority:           "U.S. Department of the Treasury, Office of Foreign Assets Control",
		DatasetID:           "ofac-sdn",
		SourceURL:           a.SourceURL,
		AcquisitionMethod:   a.Method,
		AcquiredAt:          a.AcquiredAt,
		MediaType:           a.MediaType,
		ContentLength:       a.ContentLength,
		ContentSHA256:       a.ContentSHA256,
		HTTPETag:            a.ETag,
		HTTPLastModified:    a.LastModified,
		XMLNamespace:        doc.Namespace,
		PublishDate:         doc.DateOfIssue,
		DeclaredRecordCount: len(doc.Parties),
		ParserVersion:       ParserVersion,
		SourceFormat:        SourceFormat,
		XMLSchemaVersion:    doc.Version,
		SchemaLocation:      doc.SchemaLocation,
		SourceFilename:      "SDN_ADVANCED.XML",
	}
	manifest, err = ofacsource.AssignManifestID(manifest)
	if err != nil {
		return Result{}, err
	}
	if err := ofacsource.ValidateManifest(manifest); err != nil {
		return Result{}, err
	}

	snapshot := Snapshot{
		SchemaVersion:  SnapshotSchemaVersion,
		ParserVersion:  ParserVersion,
		XMLNamespace:   doc.Namespace,
		XMLVersion:     doc.Version,
		SchemaLocation: doc.SchemaLocation,
		DateOfIssue:    doc.DateOfIssue,
		SourceManifest: manifest,
		SourceStats:    doc.Stats,
		RecordCount:    len(doc.Parties),
		Parties:        doc.Parties,
	}
	if err := assignSnapshotIdentity(&snapshot); err != nil {
		return Result{}, err
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		return Result{}, err
	}
	pkg, err := projectCompatibilityPackage(snapshot)
	if err != nil {
		return Result{}, err
	}
	return Result{Snapshot: snapshot, Package: pkg}, nil
}

func parseDocument(data []byte) (parsedDocument, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	root, err := readRoot(dec)
	if err != nil {
		return parsedDocument{}, err
	}
	if root.Name.Local != "Sanctions" || root.Name.Space != AdvancedXMLNamespace {
		return parsedDocument{}, fmt.Errorf("%w: unsupported root or namespace %q", ErrInvalidXML, root.Name.Space)
	}
	version := attr(root, "Version")
	if version != AdvancedXMLVersion {
		return parsedDocument{}, fmt.Errorf("%w: unsupported Advanced XML Version %q", ErrInvalidXML, version)
	}
	schemaLocation := attrSpace(root, "schemaLocation", "http://www.w3.org/2001/XMLSchema-instance")
	if schemaLocation == "" {
		schemaLocation = attr(root, "schemaLocation")
	}
	if !strings.Contains(schemaLocation, AdvancedXMLNamespace) {
		return parsedDocument{}, fmt.Errorf("%w: schemaLocation does not reference the Advanced XML namespace", ErrInvalidXML)
	}

	d := parsedDocument{
		Namespace:                 root.Name.Space,
		Version:                   version,
		SchemaLocation:            schemaLocation,
		Refs:                      refSets{sets: map[string]map[string]string{}},
		Locations:                 map[string]Address{},
		Documents:                 map[string]Identifier{},
		Sanctions:                 map[string][]sanctionData{},
		SelectedSanctionsEntryIDs: map[string]struct{}{},
	}
	seen := map[string]bool{}
	order := map[string]int{"DateOfIssue": 1, "ReferenceValueSets": 2, "Locations": 3, "IDRegDocuments": 4, "DistinctParties": 5, "ProfileRelationships": 6, "SanctionsEntries": 7, "SanctionsEntryLinks": 8}
	lastOrder := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return parsedDocument{}, fmt.Errorf("%w: root content: %v", ErrInvalidXML, err)
		}
		switch x := tok.(type) {
		case xml.StartElement:
			if x.Name.Space != AdvancedXMLNamespace {
				return parsedDocument{}, fmt.Errorf("%w: unexpected namespace on %s", ErrInvalidXML, x.Name.Local)
			}
			pos, ok := order[x.Name.Local]
			if !ok {
				return parsedDocument{}, fmt.Errorf("%w: unknown top-level element %q", ErrInvalidXML, x.Name.Local)
			}
			if seen[x.Name.Local] {
				return parsedDocument{}, fmt.Errorf("%w: duplicate top-level element %q", ErrInvalidXML, x.Name.Local)
			}
			if pos < lastOrder {
				return parsedDocument{}, fmt.Errorf("%w: top-level element %q is out of order", ErrInvalidXML, x.Name.Local)
			}
			seen[x.Name.Local] = true
			lastOrder = pos
			switch x.Name.Local {
			case "DateOfIssue":
				n, err := decodeNode(dec, x)
				if err != nil {
					return parsedDocument{}, err
				}
				d.DateOfIssue = parseDateOfIssue(n)
			case "ReferenceValueSets":
				n, err := decodeNode(dec, x)
				if err != nil {
					return parsedDocument{}, err
				}
				d.Refs = parseReferenceSets(n)
			case "Locations":
				if err := parseSection(dec, x, func(n *xmlNode) error {
					loc, err := parseLocation(n, d.Refs)
					if err != nil {
						return err
					}
					if _, exists := d.Locations[loc.SourceLocationID]; exists {
						return fmt.Errorf("%w: duplicate location %s", ErrInvalidXML, loc.SourceLocationID)
					}
					d.Locations[loc.SourceLocationID] = loc
					return nil
				}); err != nil {
					return parsedDocument{}, err
				}
			case "IDRegDocuments":
				if err := parseSection(dec, x, func(n *xmlNode) error {
					doc := parseIdentifier(n, d.Refs)
					if doc.SourceDocumentID == "" {
						return fmt.Errorf("%w: IDRegDocument missing ID", ErrInvalidXML)
					}
					if _, exists := d.Documents[doc.SourceDocumentID]; exists {
						return fmt.Errorf("%w: duplicate IDRegDocument %s", ErrInvalidXML, doc.SourceDocumentID)
					}
					d.Documents[doc.SourceDocumentID] = doc
					return nil
				}); err != nil {
					return parsedDocument{}, err
				}
			case "DistinctParties":
				if err := parseSection(dec, x, func(n *xmlNode) error {
					party, err := parseDistinctParty(n, d.Refs, d.Locations, d.Documents)
					if err != nil {
						return err
					}
					d.PartyCandidates = append(d.PartyCandidates, party)
					d.Stats.DistinctPartyCount++
					d.Stats.ProfileCount += len(party.Profiles)
					return nil
				}); err != nil {
					return parsedDocument{}, err
				}
			case "ProfileRelationships":
				if err := parseSection(dec, x, func(n *xmlNode) error {
					relationship, err := parseRelationship(n, d.Refs)
					if err != nil {
						return err
					}
					d.Relationships = append(d.Relationships, relationship)
					return nil
				}); err != nil {
					return parsedDocument{}, err
				}
			case "SanctionsEntries":
				if err := parseSection(dec, x, func(n *xmlNode) error {
					d.Stats.SanctionsEntryCount++
					sd, selected, err := parseSanctionsEntry(n, d.Refs)
					if err != nil {
						return err
					}
					if !selected {
						d.Stats.FilteredNonSDNEntryCount++
						return nil
					}
					d.Stats.SelectedSDNEntryCount++
					if _, exists := d.SelectedSanctionsEntryIDs[sd.SourceEntryID]; exists {
						return fmt.Errorf("%w: duplicate SanctionsEntry ID %s", ErrInvalidXML, sd.SourceEntryID)
					}
					d.SelectedSanctionsEntryIDs[sd.SourceEntryID] = struct{}{}
					d.Sanctions[sd.ProfileID] = append(d.Sanctions[sd.ProfileID], sd)
					return nil
				}); err != nil {
					return parsedDocument{}, err
				}
			case "SanctionsEntryLinks":
				if err := skipSection(dec, x); err != nil {
					return parsedDocument{}, err
				}
			}
		case xml.Directive:
			return parsedDocument{}, fmt.Errorf("%w: XML directives and DOCTYPE are prohibited", ErrInvalidXML)
		case xml.ProcInst:
			return parsedDocument{}, fmt.Errorf("%w: processing instructions are prohibited", ErrInvalidXML)
		case xml.EndElement:
			if x.Name == root.Name {
				if d.DateOfIssue == "" || !seen["ReferenceValueSets"] || !seen["DistinctParties"] || !seen["SanctionsEntries"] {
					return parsedDocument{}, fmt.Errorf("%w: required top-level sections are missing", ErrInvalidXML)
				}
				if err := finalizeDocument(&d); err != nil {
					return parsedDocument{}, err
				}
				return d, nil
			}
		}
	}
}

func readRoot(dec *xml.Decoder) (xml.StartElement, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return xml.StartElement{}, fmt.Errorf("%w: root: %v", ErrInvalidXML, err)
		}
		switch x := tok.(type) {
		case xml.ProcInst:
			if strings.ToLower(x.Target) != "xml" {
				return xml.StartElement{}, fmt.Errorf("%w: processing instruction prohibited", ErrInvalidXML)
			}
		case xml.Directive:
			return xml.StartElement{}, fmt.Errorf("%w: XML directives and DOCTYPE are prohibited", ErrInvalidXML)
		case xml.CharData:
			if strings.TrimSpace(string(x)) != "" {
				return xml.StartElement{}, fmt.Errorf("%w: content before root", ErrInvalidXML)
			}
		case xml.StartElement:
			return x, nil
		}
	}
}

func parseSection(dec *xml.Decoder, start xml.StartElement, fn func(*xmlNode) error) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: parse %s: %v", ErrInvalidXML, start.Name.Local, err)
		}
		switch x := tok.(type) {
		case xml.StartElement:
			n, err := decodeNode(dec, x)
			if err != nil {
				return err
			}
			if err := fn(n); err != nil {
				return err
			}
		case xml.CharData:
			if strings.TrimSpace(string(x)) != "" {
				return fmt.Errorf("%w: unexpected text in %s", ErrInvalidXML, start.Name.Local)
			}
		case xml.Directive:
			return fmt.Errorf("%w: directives prohibited", ErrInvalidXML)
		case xml.ProcInst:
			return fmt.Errorf("%w: processing instructions prohibited", ErrInvalidXML)
		case xml.EndElement:
			if x.Name == start.Name {
				return nil
			}
		}
	}
}

func skipSection(dec *xml.Decoder, start xml.StartElement) error {
	return parseSection(dec, start, func(*xmlNode) error { return nil })
}

func decodeNode(dec *xml.Decoder, start xml.StartElement) (*xmlNode, error) {
	n := &xmlNode{Name: start.Name.Local, Attrs: map[string]string{}}
	for _, a := range start.Attr {
		key := a.Name.Local
		if a.Name.Space != "" {
			key = a.Name.Space + "|" + a.Name.Local
		}
		n.Attrs[key] = strings.TrimSpace(a.Value)
	}
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: decode %s: %v", ErrInvalidXML, start.Name.Local, err)
		}
		switch x := tok.(type) {
		case xml.StartElement:
			child, err := decodeNode(dec, x)
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, child)
		case xml.CharData:
			text.Write([]byte(x))
		case xml.Directive:
			return nil, fmt.Errorf("%w: directives prohibited", ErrInvalidXML)
		case xml.ProcInst:
			return nil, fmt.Errorf("%w: processing instructions prohibited", ErrInvalidXML)
		case xml.EndElement:
			if x.Name == start.Name {
				n.Text = strings.TrimSpace(text.String())
				return n, nil
			}
		}
	}
}

func parseReferenceSets(root *xmlNode) refSets {
	r := refSets{sets: map[string]map[string]string{}}
	var walk func(*xmlNode, string)
	walk = func(n *xmlNode, set string) {
		if strings.HasSuffix(n.Name, "Values") {
			set = n.Name
		}
		id := nodeAttr(n, "ID")
		value := strings.TrimSpace(n.Text)
		if id != "" && value != "" && set != "" {
			if r.sets[set] == nil {
				r.sets[set] = map[string]string{}
			}
			r.sets[set][id] = value
		}
		for _, c := range n.Children {
			walk(c, set)
		}
	}
	walk(root, "")
	return r
}

func (r refSets) lookup(id string, preferred ...string) string {
	if id == "" {
		return ""
	}
	for _, set := range preferred {
		if v := r.sets[set][id]; v != "" {
			return v
		}
	}
	var found string
	for _, set := range r.sets {
		if v := set[id]; v != "" {
			if found != "" && found != v {
				return found
			}
			found = v
		}
	}
	return found
}

func parseDateOfIssue(n *xmlNode) string {
	if v := strings.TrimSpace(n.Text); v != "" {
		return v
	}
	return formatDateNode(n)
}

func parseLocation(n *xmlNode, refs refSets) (Address, error) {
	id := nodeAttr(n, "ID")
	if id == "" {
		return Address{}, fmt.Errorf("%w: Location missing ID", ErrInvalidXML)
	}
	a := Address{SourceLocationID: id}
	for _, country := range directChildren(n, "LocationCountry") {
		a.CountryID = nodeAttr(country, "CountryID")
		a.Country = refs.lookup(a.CountryID, "CountryValues")
		if a.Country != "" {
			break
		}
	}
	for _, part := range directChildren(n, "LocationPart") {
		typeID := nodeAttr(part, "LocPartTypeID")
		typ := refs.lookup(typeID, "LocPartTypeValues")
		value := primaryLocationPartValue(part)
		if value == "" {
			continue
		}
		component := AddressComponent{Type: typ, TypeID: typeID, Value: value}
		a.Components = append(a.Components, component)
		assignAddressField(&a, typ, value)
	}
	if a.Country == "" {
		for _, part := range a.Components {
			if strings.Contains(strings.ToLower(part.Type), "country") {
				a.Country = part.Value
				break
			}
		}
	}
	return a, nil
}

func primaryLocationPartValue(part *xmlNode) string {
	values := directChildren(part, "LocationPartValue")
	for _, value := range values {
		if parseBool(nodeAttr(value, "Primary")) {
			return firstDescText(value, "Value")
		}
	}
	if len(values) > 0 {
		return firstDescText(values[0], "Value")
	}
	return ""
}

func assignAddressField(a *Address, typ, value string) {
	key := strings.ToLower(strings.TrimSpace(typ))
	switch {
	case strings.Contains(key, "postal") || strings.Contains(key, "zip"):
		if a.PostalCode == "" {
			a.PostalCode = value
		}
	case strings.Contains(key, "city") || strings.Contains(key, "town"):
		if a.City == "" {
			a.City = value
		}
	case strings.Contains(key, "state") || strings.Contains(key, "province") || strings.Contains(key, "region"):
		if a.State == "" {
			a.State = value
		}
	case strings.Contains(key, "country"):
		if a.Country == "" {
			a.Country = value
		}
	case strings.Contains(key, "address") || strings.Contains(key, "street") || strings.Contains(key, "building"):
		if a.Address1 == "" {
			a.Address1 = value
		} else if a.Address2 == "" {
			a.Address2 = value
		} else if a.Address3 == "" {
			a.Address3 = value
		}
	default:
		if a.Address1 == "" {
			a.Address1 = value
		} else if a.Address2 == "" {
			a.Address2 = value
		} else if a.Address3 == "" {
			a.Address3 = value
		}
	}
}

func parseIdentifier(n *xmlNode, refs refSets) Identifier {
	id := nodeAttr(n, "ID")
	typeID := nodeAttr(n, "IDRegDocTypeID")
	identity := Identifier{
		SourceDocumentID: id,
		SourceIdentityID: nodeAttr(n, "IdentityID"),
		TypeID:           typeID,
		Type:             firstNonEmpty(refs.lookup(typeID, "IDRegDocTypeValues"), typeID),
		Number:           firstDescText(n, "IDRegistrationNo"),
		IssuingAuthority: firstDescText(n, "IssuingAuthority"),
		CountryID:        nodeAttr(n, "IssuedBy-CountryID"),
	}
	identity.Country = refs.lookup(identity.CountryID, "CountryValues")
	for _, date := range directChildren(n, "DocumentDate") {
		dateTypeID := nodeAttr(date, "IDRegDocDateTypeID")
		dateType := strings.ToLower(refs.lookup(dateTypeID, "IDRegDocDateTypeValues"))
		value := formatDateNode(date)
		if strings.Contains(dateType, "expir") || strings.Contains(dateType, "cancel") {
			identity.ExpiryDate = value
		} else if strings.Contains(dateType, "issu") || identity.IssueDate == "" {
			identity.IssueDate = value
		}
	}
	return identity
}

func parseDistinctParty(n *xmlNode, refs refSets, locations map[string]Address, documents map[string]Identifier) (partyCandidate, error) {
	uidRaw := firstAttr(n, "FixedRef", "ID")
	uid, err := strconv.Atoi(uidRaw)
	if err != nil || uid <= 0 {
		return partyCandidate{}, fmt.Errorf("%w: DistinctParty has invalid FixedRef %q", ErrInvalidXML, uidRaw)
	}
	profileNodes := directChildren(n, "Profile")
	if len(profileNodes) == 0 {
		return partyCandidate{}, fmt.Errorf("%w: DistinctParty %d has no Profile", ErrInvalidXML, uid)
	}
	candidate := partyCandidate{UID: uid, Remarks: joinDirectComments(n)}
	seenProfiles := map[string]struct{}{}
	for _, profileNode := range profileNodes {
		profile, err := parseProfile(profileNode, uid, candidate.Remarks, refs, locations, documents)
		if err != nil {
			return partyCandidate{}, err
		}
		if _, exists := seenProfiles[profile.ProfileID]; exists {
			return partyCandidate{}, fmt.Errorf("%w: DistinctParty %d contains duplicate ProfileID %s", ErrInvalidXML, uid, profile.ProfileID)
		}
		seenProfiles[profile.ProfileID] = struct{}{}
		candidate.Profiles = append(candidate.Profiles, profile)
	}
	return candidate, nil
}

func parseProfile(profile *xmlNode, uid int, remarks string, refs refSets, locations map[string]Address, documents map[string]Identifier) (Party, error) {
	profileID := nodeAttr(profile, "ID")
	if profileID == "" {
		return Party{}, fmt.Errorf("%w: DistinctParty %d Profile missing ID", ErrInvalidXML, uid)
	}
	partyTypeID := nodeAttr(profile, "PartySubTypeID")
	partyType := firstNonEmpty(refs.lookup(partyTypeID, "PartySubTypeValues"), "Entity")
	identities := directChildren(profile, "Identity")
	if len(identities) == 0 {
		return Party{}, fmt.Errorf("%w: profile %s has no Identity", ErrInvalidXML, profileID)
	}
	p := Party{
		UID:          uid,
		ProfileID:    profileID,
		ProfileIDs:   []string{profileID},
		EntityType:   partyType,
		EntityTypeID: partyTypeID,
		Remarks:      remarks,
	}
	var referencedDocs []string
	for _, identity := range identities {
		identityID := nodeAttr(identity, "ID")
		if identityID == "" {
			return Party{}, fmt.Errorf("%w: profile %s Identity missing ID", ErrInvalidXML, profileID)
		}
		p.IdentityIDs = append(p.IdentityIDs, identityID)
		partTypes := map[string]namePartGroup{}
		for _, group := range descendants(identity, "NamePartGroup") {
			groupID := nodeAttr(group, "ID")
			typeID := nodeAttr(group, "NamePartTypeID")
			if groupID != "" {
				partTypes[groupID] = namePartGroup{TypeID: typeID, Type: refs.lookup(typeID, "NamePartTypeValues")}
			}
		}
		for _, alias := range directChildren(identity, "Alias") {
			names, docRefs := parseAlias(alias, refs, partTypes)
			p.Names = append(p.Names, names...)
			referencedDocs = append(referencedDocs, docRefs...)
		}
		for id, doc := range documents {
			if doc.SourceIdentityID == identityID || referencesIdentity(identity, id, identityID) {
				p.Identifiers = append(p.Identifiers, doc)
			}
		}
	}
	p.IdentityIDs = uniqueStrings(p.IdentityIDs)
	if len(p.IdentityIDs) > 0 {
		p.IdentityID = p.IdentityIDs[0]
	}
	p.Names = uniqueNames(p.Names)
	if len(p.Names) == 0 {
		return Party{}, fmt.Errorf("%w: profile %s has no names", ErrInvalidXML, profileID)
	}
	p.PrimaryName = choosePrimaryName(p.Names)
	if p.PrimaryName == "" {
		return Party{}, fmt.Errorf("%w: profile %s has no primary name", ErrInvalidXML, profileID)
	}

	for _, featureNode := range directChildren(profile, "Feature") {
		feature := parseFeature(featureNode, refs)
		p.Features = append(p.Features, feature)
		applyFeature(&p, feature, locations)
	}
	for _, docID := range uniqueStrings(referencedDocs) {
		if doc, ok := documents[docID]; ok {
			p.Identifiers = append(p.Identifiers, doc)
		}
	}
	p.Identifiers = uniqueIdentifiers(p.Identifiers)
	p.Addresses = uniqueAddresses(p.Addresses)
	p.Features = uniqueFeatures(p.Features)
	return p, nil
}

type namePartGroup struct{ TypeID, Type string }

func parseAlias(alias *xmlNode, refs refSets, groups map[string]namePartGroup) ([]Name, []string) {
	aliasID := firstAttr(alias, "FixedRef", "ID")
	primary := parseBool(nodeAttr(alias, "Primary"))
	lowQuality := parseBool(nodeAttr(alias, "LowQuality"))
	aliasTypeID := firstAttr(alias, "AliasTypeID")
	aliasType := refs.lookup(aliasTypeID, "AliasTypeValues")
	var names []Name
	var docRefs []string
	for _, documented := range descendants(alias, "DocumentedName") {
		if documented.Name != "DocumentedName" {
			continue
		}
		name := Name{SourceAliasID: aliasID, SourceDocumentedNameID: firstAttr(documented, "FixedRef", "ID"), Primary: primary, LowQuality: lowQuality, AliasType: aliasType}
		for _, documentedPart := range directChildren(documented, "DocumentedNamePart") {
			valueNodes := directChildren(documentedPart, "NamePartValue")
			if len(valueNodes) == 0 {
				continue
			}
			partNode := valueNodes[0]
			groupID := nodeAttr(partNode, "NamePartGroupID")
			group := groups[groupID]
			scriptID := nodeAttr(partNode, "ScriptID")
			value := nodeAttr(documentedPart, "LeadingChars") + strings.TrimSpace(partNode.Text) + nodeAttr(documentedPart, "TrailingChars")
			part := NamePart{Value: strings.TrimSpace(value), PartType: group.Type, PartTypeID: group.TypeID, ScriptID: scriptID, Script: refs.lookup(scriptID, "ScriptValues"), ScriptStatus: refs.lookup(nodeAttr(partNode, "ScriptStatusID"), "ScriptStatusValues"), Acronym: parseBool(nodeAttr(partNode, "Acronym")), SourceGroupID: groupID}
			if part.Value != "" {
				name.Parts = append(name.Parts, part)
			}
		}
		name.Value = joinNameParts(name.Parts)
		if len(name.Parts) > 0 {
			name.ScriptID = name.Parts[0].ScriptID
			name.Script = name.Parts[0].Script
		}
		if name.Value != "" {
			names = append(names, name)
		}
		for _, ref := range descendants(documented, "IDRegDocumentReference") {
			if id := firstAttr(ref, "IDRegDocumentID", "ID", "RefID"); id != "" {
				docRefs = append(docRefs, id)
			}
		}
	}
	return names, docRefs
}

func joinNameParts(parts []NamePart) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part.Value) != "" {
			values = append(values, strings.TrimSpace(part.Value))
		}
	}
	return strings.Join(values, " ")
}

func choosePrimaryName(names []Name) string {
	for _, n := range names {
		if n.Primary && isLatin(n.Script) {
			return n.Value
		}
	}
	for _, n := range names {
		if n.Primary {
			return n.Value
		}
	}
	for _, n := range names {
		if isLatin(n.Script) {
			return n.Value
		}
	}
	if len(names) > 0 {
		return names[0].Value
	}
	return ""
}

func isLatin(script string) bool {
	return script == "" || strings.Contains(strings.ToLower(script), "latin")
}

func parseFeature(n *xmlNode, refs refSets) Feature {
	typeID := firstAttr(n, "FeatureTypeID")
	f := Feature{SourceFeatureID: firstAttr(n, "ID", "FixedRef"), TypeID: typeID, Type: firstNonEmpty(refs.lookup(typeID, "FeatureTypeValues"), typeID)}
	for _, version := range descendants(n, "FeatureVersion") {
		if version.Name != "FeatureVersion" {
			continue
		}
		for _, detail := range descendants(version, "VersionDetail") {
			detailTypeID := firstAttr(detail, "DetailTypeID", "VersionDetailTypeID")
			f.Details = append(f.Details, FeatureDetail{TypeID: detailTypeID, Type: refs.lookup(detailTypeID, "DetailTypeValues", "VersionDetailTypeValues"), Value: strings.TrimSpace(detail.Text)})
		}
		for _, loc := range descendants(version, "VersionLocation") {
			locID := firstAttr(loc, "LocationID", "ID", "RefID")
			if locID != "" {
				f.Details = append(f.Details, FeatureDetail{LocationID: locID})
			}
		}
		for _, period := range descendants(version, "DatePeriod") {
			value := formatDateNode(period)
			if value != "" {
				f.Details = append(f.Details, FeatureDetail{DatePeriod: value})
			}
		}
	}
	if len(f.Details) == 0 {
		if value := firstDescText(n, "VersionDetail"); value != "" {
			f.Details = append(f.Details, FeatureDetail{Value: value})
		}
	}
	return f
}

func applyFeature(p *Party, f Feature, locations map[string]Address) {
	key := strings.ToLower(f.Type)
	for _, d := range f.Details {
		value := firstNonEmpty(d.Value, d.DatePeriod)
		if d.LocationID != "" {
			if a, ok := locations[d.LocationID]; ok {
				p.Addresses = append(p.Addresses, a)
			}
			continue
		}
		if value == "" {
			continue
		}
		switch {
		case strings.Contains(key, "date of birth"):
			// Kept in feature details and projected into the compatibility package.
		case strings.Contains(key, "place of birth"):
		case strings.Contains(key, "nationality"):
		case strings.Contains(key, "citizenship"):
		case strings.Contains(key, "title") || strings.Contains(key, "position"):
		case strings.Contains(key, "digital currency address"):
			p.Identifiers = append(p.Identifiers, Identifier{SourceDocumentID: f.SourceFeatureID, Type: f.Type, TypeID: f.TypeID, Number: value})
		}
	}
}

func parseRelationship(n *xmlNode, refs refSets) (Relationship, error) {
	typeID := nodeAttr(n, "RelationTypeID")
	qualityID := nodeAttr(n, "RelationQualityID")
	relationship := Relationship{
		SanctionsEntryID:     nodeAttr(n, "SanctionsEntryID"),
		SourceRelationshipID: nodeAttr(n, "ID"),
		FromProfileID:        nodeAttr(n, "From-ProfileID"),
		ToProfileID:          nodeAttr(n, "To-ProfileID"),
		TypeID:               typeID,
		Type:                 refs.lookup(typeID, "RelationTypeValues"),
		QualityID:            qualityID,
		Quality:              refs.lookup(qualityID, "RelationQualityValues"),
		Former:               parseBool(nodeAttr(n, "Former")),
		Comment:              joinDirectComments(n),
	}
	if relationship.SourceRelationshipID == "" || relationship.FromProfileID == "" || relationship.ToProfileID == "" || relationship.SanctionsEntryID == "" {
		return Relationship{}, fmt.Errorf("%w: ProfileRelationship is missing an XSD-required identifier", ErrInvalidXML)
	}
	return relationship, nil
}

func normalizeReferenceValue(value string) string {
	return strings.ToUpper(strings.Join(strings.Fields(strings.TrimSpace(value)), " "))
}

func isSDNListLabel(value string) bool {
	return normalizeReferenceValue(value) == normalizeReferenceValue(OfficialSDNListName)
}

func resolveSanctionsEntryList(n *xmlNode, refs refSets) (string, string, error) {
	listID := nodeAttr(n, "ListID")
	if listID != "" {
		list := refs.lookup(listID, "ListValues")
		if list == "" {
			return "", "", fmt.Errorf("%w: SanctionsEntry references unknown ListID %s", ErrInvalidXML, listID)
		}
		return listID, list, nil
	}

	// ListID is optional in the XSD. It is operationally safe to infer only
	// when the document data dictionary contains exactly one List value.
	values := refs.sets["ListValues"]
	if len(values) != 1 {
		return "", "", fmt.Errorf("%w: SanctionsEntry without ListID is ambiguous across %d ListValues", ErrInvalidXML, len(values))
	}
	for id, value := range values {
		return id, value, nil
	}
	panic("unreachable")
}

func parseSanctionsEntry(n *xmlNode, refs refSets) (sanctionData, bool, error) {
	entryID := nodeAttr(n, "ID")
	profileID := nodeAttr(n, "ProfileID")
	if entryID == "" || profileID == "" {
		return sanctionData{}, false, fmt.Errorf("%w: SanctionsEntry missing XSD-required ID or ProfileID", ErrInvalidXML)
	}
	listID, list, err := resolveSanctionsEntryList(n, refs)
	if err != nil {
		return sanctionData{}, false, err
	}
	sd := sanctionData{SourceEntryID: entryID, ProfileID: profileID, ListID: listID, List: list}
	if !isSDNListLabel(list) {
		return sd, false, nil
	}
	for _, measure := range directChildren(n, "SanctionsMeasure") {
		typeID := nodeAttr(measure, "SanctionsTypeID")
		typ := refs.lookup(typeID, "SanctionsTypeValues")
		comment := joinDirectComments(measure)
		if comment == "" {
			comment = strings.TrimSpace(measure.Text)
		}
		if strings.Contains(normalizeReferenceValue(typ), "PROGRAM") && comment != "" {
			sd.Programs = append(sd.Programs, comment)
		}
	}
	for _, event := range directChildren(n, "EntryEvent") {
		authorityID := nodeAttr(event, "LegalBasisID")
		eventTypeID := nodeAttr(event, "EntryEventTypeID")
		sd.LegalAuthorities = append(sd.LegalAuthorities, LegalAuthority{
			SourceEventID: nodeAttr(event, "ID"),
			AuthorityID:   authorityID,
			Authority:     refs.lookup(authorityID, "LegalBasisValues"),
			EventTypeID:   eventTypeID,
			EventType:     refs.lookup(eventTypeID, "EntryEventTypeValues"),
			Date:          formatDateNode(event),
			Comment:       joinDirectComments(event),
		})
	}
	sd.Programs = uniqueStrings(sd.Programs)
	if len(sd.Programs) == 0 {
		return sanctionData{}, false, fmt.Errorf("%w: SDN profile %s entry %s has no Program sanctions measure", ErrInvalidXML, profileID, entryID)
	}
	return sd, true, nil
}

func finalizeDocument(d *parsedDocument) error {
	profileOwners := map[string]int{}
	seenUID := map[int]struct{}{}
	for candidateIndex, candidate := range d.PartyCandidates {
		if _, exists := seenUID[candidate.UID]; exists {
			return fmt.Errorf("%w: duplicate DistinctParty FixedRef %d", ErrInvalidXML, candidate.UID)
		}
		seenUID[candidate.UID] = struct{}{}
		for _, profile := range candidate.Profiles {
			if _, exists := profileOwners[profile.ProfileID]; exists {
				return fmt.Errorf("%w: duplicate ProfileID %s", ErrInvalidXML, profile.ProfileID)
			}
			profileOwners[profile.ProfileID] = candidateIndex
		}
	}
	for profileID := range d.Sanctions {
		if _, exists := profileOwners[profileID]; !exists {
			return fmt.Errorf("%w: SDN SanctionsEntry references unknown ProfileID %s", ErrInvalidXML, profileID)
		}
	}

	for _, candidate := range d.PartyCandidates {
		var selectedProfiles []Party
		for _, profile := range candidate.Profiles {
			if len(d.Sanctions[profile.ProfileID]) > 0 {
				selectedProfiles = append(selectedProfiles, profile)
			}
		}
		if len(selectedProfiles) == 0 {
			continue
		}
		party, err := mergeSelectedProfiles(candidate, selectedProfiles, d.Sanctions)
		if err != nil {
			return err
		}
		d.Parties = append(d.Parties, party)
	}
	if len(d.Parties) == 0 {
		return fmt.Errorf("%w: no entries resolved to %q", ErrInvalidXML, OfficialSDNListName)
	}

	selectedProfiles := map[string]int{}
	for i := range d.Parties {
		for _, profileID := range d.Parties[i].ProfileIDs {
			selectedProfiles[profileID] = i
		}
	}
	for _, relationship := range d.Relationships {
		if _, selected := d.SelectedSanctionsEntryIDs[relationship.SanctionsEntryID]; !selected {
			continue
		}
		if i, ok := selectedProfiles[relationship.FromProfileID]; ok {
			d.Parties[i].Relationships = append(d.Parties[i].Relationships, relationship)
		}
	}
	for i := range d.Parties {
		sortParty(&d.Parties[i])
	}
	sort.Slice(d.Parties, func(i, j int) bool { return d.Parties[i].UID < d.Parties[j].UID })
	return nil
}

func mergeSelectedProfiles(candidate partyCandidate, profiles []Party, sanctions map[string][]sanctionData) (Party, error) {
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ProfileID < profiles[j].ProfileID })
	merged := Party{UID: candidate.UID, Remarks: candidate.Remarks}
	var normalizedType string
	for _, profile := range profiles {
		profileType := normalizeEntityType(profile.EntityType)
		if normalizedType == "" {
			normalizedType = profileType
			merged.EntityType = profile.EntityType
			merged.EntityTypeID = profile.EntityTypeID
		} else if profileType != normalizedType {
			return Party{}, fmt.Errorf("%w: DistinctParty %d has conflicting SDN profile entity types %s and %s", ErrInvalidXML, candidate.UID, normalizedType, profileType)
		}
		merged.ProfileIDs = append(merged.ProfileIDs, profile.ProfileIDs...)
		merged.IdentityIDs = append(merged.IdentityIDs, profile.IdentityIDs...)
		merged.Names = append(merged.Names, profile.Names...)
		merged.Addresses = append(merged.Addresses, profile.Addresses...)
		merged.Identifiers = append(merged.Identifiers, profile.Identifiers...)
		merged.Features = append(merged.Features, profile.Features...)
		for _, sd := range sanctions[profile.ProfileID] {
			merged.Programs = append(merged.Programs, sd.Programs...)
			merged.LegalAuthorities = append(merged.LegalAuthorities, sd.LegalAuthorities...)
		}
	}
	merged.ProfileIDs = uniqueStrings(merged.ProfileIDs)
	merged.IdentityIDs = uniqueStrings(merged.IdentityIDs)
	if len(merged.ProfileIDs) > 0 {
		merged.ProfileID = merged.ProfileIDs[0]
	}
	if len(merged.IdentityIDs) > 0 {
		merged.IdentityID = merged.IdentityIDs[0]
	}
	merged.Names = uniqueNames(merged.Names)
	merged.PrimaryName = choosePrimaryName(merged.Names)
	merged.Addresses = uniqueAddresses(merged.Addresses)
	merged.Identifiers = uniqueIdentifiers(merged.Identifiers)
	merged.Features = uniqueFeatures(merged.Features)
	merged.Programs = uniqueStrings(merged.Programs)
	merged.LegalAuthorities = compactAuthorities(merged.LegalAuthorities)
	if merged.ProfileID == "" || merged.PrimaryName == "" || len(merged.Names) == 0 || len(merged.Programs) == 0 {
		return Party{}, fmt.Errorf("%w: DistinctParty %d produced an incomplete SDN projection", ErrInvalidXML, candidate.UID)
	}
	return merged, nil
}

func sortParty(p *Party) {
	sort.Strings(p.ProfileIDs)
	sort.Strings(p.IdentityIDs)
	sort.Strings(p.Programs)
	sort.Slice(p.Names, func(i, j int) bool {
		if p.Names[i].Primary != p.Names[j].Primary {
			return p.Names[i].Primary
		}
		if p.Names[i].LowQuality != p.Names[j].LowQuality {
			return !p.Names[i].LowQuality
		}
		if p.Names[i].Value != p.Names[j].Value {
			return p.Names[i].Value < p.Names[j].Value
		}
		return p.Names[i].SourceDocumentedNameID < p.Names[j].SourceDocumentedNameID
	})
	sort.Slice(p.Addresses, func(i, j int) bool { return p.Addresses[i].SourceLocationID < p.Addresses[j].SourceLocationID })
	sort.Slice(p.Identifiers, func(i, j int) bool { return p.Identifiers[i].SourceDocumentID < p.Identifiers[j].SourceDocumentID })
	sort.Slice(p.Features, func(i, j int) bool {
		if p.Features[i].SourceFeatureID != p.Features[j].SourceFeatureID {
			return p.Features[i].SourceFeatureID < p.Features[j].SourceFeatureID
		}
		return p.Features[i].Type < p.Features[j].Type
	})
	sort.Slice(p.Relationships, func(i, j int) bool {
		return p.Relationships[i].SourceRelationshipID < p.Relationships[j].SourceRelationshipID
	})
}

func projectCompatibilityPackage(snapshot Snapshot) (ofacsource.SourcePackage, error) {
	doc := ofacsource.Document{Namespace: snapshot.XMLNamespace, PublishDate: snapshot.DateOfIssue, RecordCount: snapshot.RecordCount}
	for _, p := range snapshot.Parties {
		e := ofacsource.Entry{UID: p.UID, LastName: p.PrimaryName, SDNType: normalizeEntityType(p.EntityType), Remarks: p.Remarks, Programs: append([]string(nil), p.Programs...)}
		aliasUID := p.UID * 1000
		for _, n := range p.Names {
			if n.Primary && n.Value == p.PrimaryName {
				continue
			}
			aliasUID++
			category := "strong"
			if n.LowQuality {
				category = "weak"
			}
			e.Aliases = append(e.Aliases, ofacsource.Alias{UID: aliasUID, Type: firstNonEmpty(n.AliasType, "a.k.a."), Category: category, LastName: n.Value})
		}
		addressUID := p.UID * 1000
		for _, a := range p.Addresses {
			addressUID++
			uid := numericOrFallback(a.SourceLocationID, addressUID)
			e.Addresses = append(e.Addresses, ofacsource.Address{UID: uid, Address1: a.Address1, Address2: a.Address2, Address3: a.Address3, City: a.City, State: a.State, PostalCode: a.PostalCode, Country: a.Country})
		}
		identifierUID := p.UID * 1000
		for _, id := range p.Identifiers {
			identifierUID++
			uid := numericOrFallback(id.SourceDocumentID, identifierUID)
			e.Identifiers = append(e.Identifiers, ofacsource.Identifier{UID: uid, Type: id.Type, Number: id.Number, Country: id.Country, Issue: id.IssueDate, Expiry: id.ExpiryDate})
		}
		for _, f := range p.Features {
			key := strings.ToLower(f.Type)
			for _, d := range f.Details {
				v := firstNonEmpty(d.Value, d.DatePeriod)
				if v == "" {
					continue
				}
				switch {
				case strings.Contains(key, "date of birth"):
					e.DatesOfBirth = append(e.DatesOfBirth, v)
				case strings.Contains(key, "place of birth"):
					e.PlacesOfBirth = append(e.PlacesOfBirth, v)
				case strings.Contains(key, "nationality"):
					e.Nationalities = append(e.Nationalities, v)
				case strings.Contains(key, "citizenship"):
					e.Citizenships = append(e.Citizenships, v)
				case strings.Contains(key, "title") || strings.Contains(key, "position"):
					if e.Title == "" {
						e.Title = v
					}
				case strings.Contains(key, "call sign"):
					e.Vessel.CallSign = v
				case strings.Contains(key, "vessel type"):
					e.Vessel.Type = v
				case strings.Contains(key, "vessel flag") || key == "flag":
					e.Vessel.Flag = v
				case strings.Contains(key, "vessel owner") || key == "owner":
					e.Vessel.Owner = v
				case strings.Contains(key, "tonnage") && !strings.Contains(key, "gross"):
					e.Vessel.Tonnage = v
				case strings.Contains(key, "gross registered") || strings.Contains(key, "grt"):
					e.Vessel.GRT = v
				}
			}
		}
		doc.Entries = append(doc.Entries, e)
	}
	pkg := ofacsource.SourcePackage{SchemaVersion: ofacsource.PackageSchemaVersion, Manifest: snapshot.SourceManifest, Document: doc}
	return pkg, nil
}

func normalizeEntityType(v string) string {
	key := strings.ToLower(v)
	switch {
	case strings.Contains(key, "individual") || strings.Contains(key, "person"):
		return "Individual"
	case strings.Contains(key, "vessel") || strings.Contains(key, "ship"):
		return "Vessel"
	case strings.Contains(key, "aircraft") || strings.Contains(key, "airplane"):
		return "Aircraft"
	default:
		return "Entity"
	}
}

func ValidateSnapshot(s Snapshot) error {
	if s.SchemaVersion != SnapshotSchemaVersion || s.ParserVersion != ParserVersion || s.XMLNamespace != AdvancedXMLNamespace || s.XMLVersion != AdvancedXMLVersion {
		return fmt.Errorf("%w: invalid snapshot header", ErrInvalidXML)
	}
	if err := ofacsource.ValidateManifest(s.SourceManifest); err != nil {
		return fmt.Errorf("%w: source manifest: %v", ErrInvalidXML, err)
	}
	if s.RecordCount < 1 || s.RecordCount != len(s.Parties) || strings.TrimSpace(s.DateOfIssue) == "" {
		return fmt.Errorf("%w: invalid snapshot count or date", ErrInvalidXML)
	}
	if s.SourceStats.DistinctPartyCount < s.RecordCount || s.SourceStats.ProfileCount < s.RecordCount || s.SourceStats.SelectedSDNEntryCount < s.RecordCount || s.SourceStats.SanctionsEntryCount != s.SourceStats.SelectedSDNEntryCount+s.SourceStats.FilteredNonSDNEntryCount {
		return fmt.Errorf("%w: invalid source statistics", ErrInvalidXML)
	}
	last := 0
	seen := map[int]struct{}{}
	for _, p := range s.Parties {
		if p.UID <= last || strings.TrimSpace(p.PrimaryName) == "" || len(p.Programs) == 0 || len(p.Names) == 0 {
			return fmt.Errorf("%w: invalid party %d", ErrInvalidXML, p.UID)
		}
		if _, ok := seen[p.UID]; ok {
			return fmt.Errorf("%w: duplicate party %d", ErrInvalidXML, p.UID)
		}
		seen[p.UID] = struct{}{}
		last = p.UID
	}
	wantID, wantChecksum, err := snapshotIdentity(s)
	if err != nil {
		return err
	}
	if s.SnapshotID != wantID || s.SnapshotChecksum != wantChecksum {
		return fmt.Errorf("%w: snapshot identity mismatch", ErrInvalidXML)
	}
	return nil
}

func assignSnapshotIdentity(s *Snapshot) error {
	id, checksum, err := snapshotIdentity(*s)
	if err != nil {
		return err
	}
	s.SnapshotID, s.SnapshotChecksum = id, checksum
	return nil
}

func snapshotIdentity(s Snapshot) (string, string, error) {
	material := struct {
		SchemaVersion  string      `json:"schema_version"`
		ParserVersion  string      `json:"parser_version"`
		XMLNamespace   string      `json:"xml_namespace"`
		XMLVersion     string      `json:"xml_version"`
		SchemaLocation string      `json:"schema_location"`
		DateOfIssue    string      `json:"date_of_issue"`
		SourceSHA256   string      `json:"source_sha256"`
		SourceStats    SourceStats `json:"source_stats"`
		RecordCount    int         `json:"record_count"`
		Parties        []Party     `json:"parties"`
	}{s.SchemaVersion, s.ParserVersion, s.XMLNamespace, s.XMLVersion, s.SchemaLocation, s.DateOfIssue, s.SourceManifest.ContentSHA256, s.SourceStats, s.RecordCount, s.Parties}
	b, err := json.Marshal(material)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(b)
	checksum := hex.EncodeToString(sum[:])
	return "ofac_advanced_snapshot_" + checksum[:24], checksum, nil
}

func attr(start xml.StartElement, local string) string {
	for _, a := range start.Attr {
		if a.Name.Local == local {
			return strings.TrimSpace(a.Value)
		}
	}
	return ""
}
func attrSpace(start xml.StartElement, local, space string) string {
	for _, a := range start.Attr {
		if a.Name.Local == local && a.Name.Space == space {
			return strings.TrimSpace(a.Value)
		}
	}
	return ""
}
func nodeAttr(n *xmlNode, local string) string {
	if n == nil {
		return ""
	}
	if v := n.Attrs[local]; v != "" {
		return v
	}
	for k, v := range n.Attrs {
		if strings.HasSuffix(k, "|"+local) {
			return v
		}
	}
	return ""
}
func firstAttr(n *xmlNode, names ...string) string {
	for _, name := range names {
		if v := nodeAttr(n, name); v != "" {
			return v
		}
	}
	return ""
}
func directChildren(n *xmlNode, name string) []*xmlNode {
	var out []*xmlNode
	for _, c := range n.Children {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}
func descendants(n *xmlNode, name string) []*xmlNode {
	var out []*xmlNode
	var walk func(*xmlNode)
	walk = func(x *xmlNode) {
		for _, c := range x.Children {
			if c.Name == name {
				out = append(out, c)
			}
			walk(c)
		}
	}
	walk(n)
	return out
}
func firstDescText(n *xmlNode, names ...string) string {
	for _, name := range names {
		for _, d := range descendants(n, name) {
			if strings.TrimSpace(d.Text) != "" {
				return strings.TrimSpace(d.Text)
			}
		}
	}
	return ""
}
func joinDirectComments(n *xmlNode) string {
	var values []string
	for _, c := range n.Children {
		if c.Name == "Comment" && strings.TrimSpace(c.Text) != "" {
			values = append(values, strings.TrimSpace(c.Text))
		}
	}
	return strings.Join(values, " | ")
}
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
func parseBool(v string) bool { b, _ := strconv.ParseBool(strings.TrimSpace(v)); return b }
func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func numericOrFallback(v string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err == nil && n > 0 {
		return n
	}
	return fallback
}

func referencesIdentity(n *xmlNode, docID, identityID string) bool {
	if identityID == "" {
		return false
	}
	for _, ref := range descendants(n, "IDRegDocumentReference") {
		if firstAttr(ref, "IDRegDocumentID", "ID", "RefID") == docID {
			return true
		}
	}
	return false
}

func uniqueNames(values []Name) []Name {
	seen := map[string]struct{}{}
	var out []Name
	for _, value := range values {
		if strings.TrimSpace(value.Value) == "" {
			continue
		}
		key := strings.Join([]string{
			value.SourceAliasID,
			value.SourceDocumentedNameID,
			value.Value,
			value.ScriptID,
			strconv.FormatBool(value.Primary),
			strconv.FormatBool(value.LowQuality),
		}, "\x1f")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func uniqueFeatures(values []Feature) []Feature {
	seen := map[string]struct{}{}
	var out []Feature
	for _, value := range values {
		key := value.SourceFeatureID
		if key == "" {
			encoded, _ := json.Marshal(value)
			key = string(encoded)
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func uniqueIdentifiers(values []Identifier) []Identifier {
	seen := map[string]struct{}{}
	var out []Identifier
	for _, v := range values {
		key := v.SourceDocumentID + "\x1f" + v.Type + "\x1f" + v.Number
		if strings.TrimSpace(v.Number) == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	return out
}
func uniqueAddresses(values []Address) []Address {
	seen := map[string]struct{}{}
	var out []Address
	for _, v := range values {
		key := v.SourceLocationID
		if key == "" {
			key = v.Address1 + "\x1f" + v.City + "\x1f" + v.Country
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	return out
}
func compactAuthorities(values []LegalAuthority) []LegalAuthority {
	var out []LegalAuthority
	for _, v := range values {
		if v.Authority == "" && v.EventType == "" && v.Date == "" && v.Comment == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func formatDateNode(n *xmlNode) string {
	if n == nil {
		return ""
	}
	// Prefer a direct YYYY-MM-DD-like text value.
	if v := strings.TrimSpace(n.Text); v != "" && containsDigit(v) {
		return v
	}
	for _, name := range []string{"Date", "From", "To"} {
		for _, candidate := range descendants(n, name) {
			if v := dateParts(candidate); v != "" {
				return v
			}
		}
	}
	if v := dateParts(n); v != "" {
		return v
	}
	var start, end string
	for _, s := range descendants(n, "Start") {
		start = formatBoundary(s)
		if start != "" {
			break
		}
	}
	for _, e := range descendants(n, "End") {
		end = formatBoundary(e)
		if end != "" {
			break
		}
	}
	if start != "" && end != "" {
		if start == end {
			return start
		}
		return start + " to " + end
	}
	return firstNonEmpty(start, end)
}
func formatBoundary(n *xmlNode) string {
	var from, to string
	for _, c := range n.Children {
		if c.Name == "From" {
			from = dateParts(c)
		}
		if c.Name == "To" {
			to = dateParts(c)
		}
	}
	if from != "" && to != "" {
		if from == to {
			return from
		}
		return from + " to " + to
	}
	return firstNonEmpty(from, to, dateParts(n))
}
func dateParts(n *xmlNode) string {
	y := firstDescText(n, "Year")
	m := firstDescText(n, "Month")
	d := firstDescText(n, "Day")
	if y == "" {
		return ""
	}
	if m == "" {
		return y
	}
	mi, _ := strconv.Atoi(m)
	if d == "" {
		return fmt.Sprintf("%s-%02d", y, mi)
	}
	di, _ := strconv.Atoi(d)
	return fmt.Sprintf("%s-%02d-%02d", y, mi, di)
}
func containsDigit(v string) bool {
	for _, r := range v {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}
