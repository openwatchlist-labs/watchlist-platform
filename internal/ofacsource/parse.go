package ofacsource

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var ErrInvalidXML = errors.New("invalid OFAC SDN XML")

func Parse(a Acquired) (SourcePackage, error) {
	d, err := parseDocument(a.Bytes)
	if err != nil {
		return SourcePackage{}, err
	}
	m := SourceManifest{SchemaVersion: ManifestSchemaVersion, Authority: "U.S. Department of the Treasury, Office of Foreign Assets Control", DatasetID: "ofac-sdn", SourceURL: a.SourceURL, AcquisitionMethod: a.Method, AcquiredAt: a.AcquiredAt, MediaType: a.MediaType, ContentLength: a.ContentLength, ContentSHA256: a.ContentSHA256, HTTPETag: a.ETag, HTTPLastModified: a.LastModified, XMLNamespace: d.Namespace, PublishDate: d.PublishDate, DeclaredRecordCount: d.RecordCount, ParserVersion: ParserVersion}
	m, err = assignManifestID(m)
	if err != nil {
		return SourcePackage{}, err
	}
	if err = ValidateManifest(m); err != nil {
		return SourcePackage{}, err
	}
	return SourcePackage{SchemaVersion: PackageSchemaVersion, Manifest: m, Document: d}, nil
}

func parseDocument(data []byte) (Document, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	var root xml.StartElement
	for {
		tok, err := dec.Token()
		if err != nil {
			return Document{}, fmt.Errorf("%w: root: %v", ErrInvalidXML, err)
		}
		switch x := tok.(type) {
		case xml.ProcInst:
			if strings.ToLower(x.Target) != "xml" {
				return Document{}, fmt.Errorf("%w: processing instruction prohibited", ErrInvalidXML)
			}
		case xml.Directive:
			return Document{}, fmt.Errorf("%w: XML directives and DOCTYPE are prohibited", ErrInvalidXML)
		case xml.CharData:
			if strings.TrimSpace(string(x)) != "" {
				return Document{}, fmt.Errorf("%w: content before root", ErrInvalidXML)
			}
		case xml.StartElement:
			root = x
			goto found
		}
	}
found:
	if root.Name.Local != "sdnList" || root.Name.Space != LegacyXMLNamespace {
		return Document{}, fmt.Errorf("%w: unsupported root or namespace %q", ErrInvalidXML, root.Name.Space)
	}
	d := Document{Namespace: root.Name.Space}
	seen := map[int]struct{}{}
	seenPublish := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return Document{}, fmt.Errorf("%w: root content: %v", ErrInvalidXML, err)
		}
		switch x := tok.(type) {
		case xml.StartElement:
			switch x.Name.Local {
			case "publishInformation", "publshInformation":
				if seenPublish {
					return Document{}, fmt.Errorf("%w: duplicate publication metadata", ErrInvalidXML)
				}
				seenPublish = true
				d.PublishDate, d.RecordCount, err = parsePublish(dec, x)
			case "sdnEntry":
				var e Entry
				e, err = parseEntry(dec, x)
				if err == nil {
					if _, ok := seen[e.UID]; ok {
						return Document{}, fmt.Errorf("%w: duplicate UID %d", ErrInvalidXML, e.UID)
					}
					seen[e.UID] = struct{}{}
					d.Entries = append(d.Entries, e)
				}
			default:
				return Document{}, fmt.Errorf("%w: unknown root element %q", ErrInvalidXML, x.Name.Local)
			}
			if err != nil {
				return Document{}, err
			}
		case xml.Directive:
			return Document{}, fmt.Errorf("%w: directives prohibited", ErrInvalidXML)
		case xml.ProcInst:
			return Document{}, fmt.Errorf("%w: processing instruction prohibited", ErrInvalidXML)
		case xml.EndElement:
			if x.Name == root.Name {
				if !seenPublish || d.PublishDate == "" || d.RecordCount < 1 {
					return Document{}, fmt.Errorf("%w: publish date and positive record count required", ErrInvalidXML)
				}
				if d.RecordCount != len(d.Entries) {
					return Document{}, fmt.Errorf("%w: declared record count %d does not match parsed entries %d", ErrInvalidXML, d.RecordCount, len(d.Entries))
				}
				return d, nil
			}
		}
	}
}

func parsePublish(dec *xml.Decoder, start xml.StartElement) (string, int, error) {
	var date string
	var count int
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", 0, err
		}
		switch x := tok.(type) {
		case xml.StartElement:
			v, err := readText(dec, x)
			if err != nil {
				return "", 0, err
			}
			switch x.Name.Local {
			case "Publish_Date":
				date = v
			case "Record_Count":
				count, err = strconv.Atoi(v)
				if err != nil {
					return "", 0, fmt.Errorf("%w: invalid Record_Count", ErrInvalidXML)
				}
			default:
				return "", 0, fmt.Errorf("%w: unknown publishInformation element %q", ErrInvalidXML, x.Name.Local)
			}
		case xml.EndElement:
			if x.Name == start.Name {
				return date, count, nil
			}
		}
	}
}

func parseEntry(dec *xml.Decoder, start xml.StartElement) (Entry, error) {
	var e Entry
	for {
		tok, err := dec.Token()
		if err != nil {
			return Entry{}, err
		}
		switch x := tok.(type) {
		case xml.StartElement:
			var err error
			switch x.Name.Local {
			case "uid":
				e.UID, err = readInt(dec, x)
			case "firstName":
				e.FirstName, err = readText(dec, x)
			case "lastName":
				e.LastName, err = readText(dec, x)
			case "sdnType":
				e.SDNType, err = readText(dec, x)
			case "title":
				e.Title, err = readText(dec, x)
			case "remarks":
				e.Remarks, err = readText(dec, x)
			case "programList":
				e.Programs, err = parseTextList(dec, x, "program")
			case "akaList":
				e.Aliases, err = parseAliases(dec, x)
			case "addressList":
				e.Addresses, err = parseAddresses(dec, x)
			case "idList":
				e.Identifiers, err = parseIdentifiers(dec, x)
			case "dateOfBirthList":
				e.DatesOfBirth, err = parseObjectValues(dec, x, "dateOfBirthItem", "dateOfBirth")
			case "placeOfBirthList":
				e.PlacesOfBirth, err = parseObjectValues(dec, x, "placeOfBirthItem", "placeOfBirth")
			case "nationalityList":
				e.Nationalities, err = parseObjectValues(dec, x, "nationality", "country")
			case "citizenshipList":
				e.Citizenships, err = parseObjectValues(dec, x, "citizenship", "country")
			case "vesselInfo":
				e.Vessel, err = parseVessel(dec, x)
			default:
				return Entry{}, fmt.Errorf("%w: unknown sdnEntry element %q", ErrInvalidXML, x.Name.Local)
			}
			if err != nil {
				return Entry{}, err
			}
		case xml.EndElement:
			if x.Name == start.Name {
				if e.UID <= 0 || joinName(e.FirstName, e.LastName) == "" || e.SDNType == "" || len(e.Programs) == 0 {
					return Entry{}, fmt.Errorf("%w: entry requires uid, name, type, and program", ErrInvalidXML)
				}
				return e, nil
			}
		}
	}
}

func parseAliases(dec *xml.Decoder, start xml.StartElement) ([]Alias, error) {
	var out []Alias
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch x := tok.(type) {
		case xml.StartElement:
			if x.Name.Local != "aka" {
				return nil, fmt.Errorf("%w: unknown akaList element %q", ErrInvalidXML, x.Name.Local)
			}
			var a Alias
			err = parseFields(dec, x, map[string]func(string) error{"uid": func(v string) error { n, e := strconv.Atoi(v); a.UID = n; return e }, "type": func(v string) error { a.Type = v; return nil }, "category": func(v string) error { a.Category = v; return nil }, "firstName": func(v string) error { a.FirstName = v; return nil }, "lastName": func(v string) error { a.LastName = v; return nil }})
			if err != nil {
				return nil, err
			}
			if a.UID <= 0 || joinName(a.FirstName, a.LastName) == "" {
				return nil, fmt.Errorf("%w: invalid aka", ErrInvalidXML)
			}
			out = append(out, a)
		case xml.EndElement:
			if x.Name == start.Name {
				return out, nil
			}
		}
	}
}
func parseAddresses(dec *xml.Decoder, start xml.StartElement) ([]Address, error) {
	var out []Address
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch x := tok.(type) {
		case xml.StartElement:
			if x.Name.Local != "address" {
				return nil, fmt.Errorf("%w: unknown addressList element %q", ErrInvalidXML, x.Name.Local)
			}
			var a Address
			err = parseFields(dec, x, map[string]func(string) error{"uid": func(v string) error { n, e := strconv.Atoi(v); a.UID = n; return e }, "address1": func(v string) error { a.Address1 = v; return nil }, "address2": func(v string) error { a.Address2 = v; return nil }, "address3": func(v string) error { a.Address3 = v; return nil }, "city": func(v string) error { a.City = v; return nil }, "stateOrProvince": func(v string) error { a.State = v; return nil }, "postalCode": func(v string) error { a.PostalCode = v; return nil }, "country": func(v string) error { a.Country = v; return nil }})
			if err != nil {
				return nil, err
			}
			if a.UID <= 0 {
				return nil, fmt.Errorf("%w: invalid address uid", ErrInvalidXML)
			}
			out = append(out, a)
		case xml.EndElement:
			if x.Name == start.Name {
				return out, nil
			}
		}
	}
}
func parseIdentifiers(dec *xml.Decoder, start xml.StartElement) ([]Identifier, error) {
	var out []Identifier
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch x := tok.(type) {
		case xml.StartElement:
			if x.Name.Local != "id" {
				return nil, fmt.Errorf("%w: unknown idList element %q", ErrInvalidXML, x.Name.Local)
			}
			var a Identifier
			err = parseFields(dec, x, map[string]func(string) error{"uid": func(v string) error { n, e := strconv.Atoi(v); a.UID = n; return e }, "idType": func(v string) error { a.Type = v; return nil }, "idNumber": func(v string) error { a.Number = v; return nil }, "idCountry": func(v string) error { a.Country = v; return nil }, "issueDate": func(v string) error { a.Issue = v; return nil }, "expirationDate": func(v string) error { a.Expiry = v; return nil }})
			if err != nil {
				return nil, err
			}
			if a.UID <= 0 || a.Type == "" || a.Number == "" {
				return nil, fmt.Errorf("%w: invalid identifier", ErrInvalidXML)
			}
			out = append(out, a)
		case xml.EndElement:
			if x.Name == start.Name {
				return out, nil
			}
		}
	}
}
func parseVessel(dec *xml.Decoder, start xml.StartElement) (Vessel, error) {
	var v Vessel
	err := parseFields(dec, start, map[string]func(string) error{"callSign": func(x string) error { v.CallSign = x; return nil }, "vesselType": func(x string) error { v.Type = x; return nil }, "vesselFlag": func(x string) error { v.Flag = x; return nil }, "vesselOwner": func(x string) error { v.Owner = x; return nil }, "tonnage": func(x string) error { v.Tonnage = x; return nil }, "grossRegisteredTonnage": func(x string) error { v.GRT = x; return nil }})
	return v, err
}
func parseTextList(dec *xml.Decoder, start xml.StartElement, item string) ([]string, error) {
	var out []string
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch x := tok.(type) {
		case xml.StartElement:
			if x.Name.Local != item {
				return nil, fmt.Errorf("%w: unknown list element %q", ErrInvalidXML, x.Name.Local)
			}
			v, err := readText(dec, x)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		case xml.EndElement:
			if x.Name == start.Name {
				return out, nil
			}
		}
	}
}
func parseObjectValues(dec *xml.Decoder, start xml.StartElement, item, field string) ([]string, error) {
	var out []string
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch x := tok.(type) {
		case xml.StartElement:
			if x.Name.Local != item {
				return nil, fmt.Errorf("%w: unknown list item %q", ErrInvalidXML, x.Name.Local)
			}
			var value string
			err = parseFields(dec, x, map[string]func(string) error{"uid": func(string) error { return nil }, field: func(v string) error { value = v; return nil }, "mainEntry": func(string) error { return nil }})
			if err != nil {
				return nil, err
			}
			if value != "" {
				out = append(out, value)
			}
		case xml.EndElement:
			if x.Name == start.Name {
				return out, nil
			}
		}
	}
}
func parseFields(dec *xml.Decoder, start xml.StartElement, set map[string]func(string) error) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch x := tok.(type) {
		case xml.StartElement:
			f, ok := set[x.Name.Local]
			if !ok {
				return fmt.Errorf("%w: unknown %s element %q", ErrInvalidXML, start.Name.Local, x.Name.Local)
			}
			v, err := readText(dec, x)
			if err != nil {
				return err
			}
			if err = f(v); err != nil {
				return fmt.Errorf("%w: invalid %s.%s", ErrInvalidXML, start.Name.Local, x.Name.Local)
			}
		case xml.EndElement:
			if x.Name == start.Name {
				return nil
			}
		}
	}
}
func readText(dec *xml.Decoder, start xml.StartElement) (string, error) {
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch x := tok.(type) {
		case xml.CharData:
			b.Write([]byte(x))
		case xml.StartElement:
			return "", fmt.Errorf("%w: nested element %q", ErrInvalidXML, x.Name.Local)
		case xml.EndElement:
			if x.Name == start.Name {
				return strings.TrimSpace(b.String()), nil
			}
		}
	}
}
func readInt(dec *xml.Decoder, start xml.StartElement) (int, error) {
	v, err := readText(dec, start)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%w: %s must be integer", ErrInvalidXML, start.Name.Local)
	}
	return n, nil
}
func joinName(first, last string) string {
	return strings.TrimSpace(strings.TrimSpace(first) + " " + strings.TrimSpace(last))
}
