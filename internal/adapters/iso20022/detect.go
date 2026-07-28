package iso20022

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
)

const (
	Pacs00800108Namespace                              = "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08"
	Pacs00800108Definition canonical.MessageDefinition = "pacs.008.001.08"
)

var namespaceDefinitionPattern = regexp.MustCompile(`^urn:iso:std:iso:20022:tech:xsd:([a-z]+\.[0-9]{3}\.[0-9]{3}\.[0-9]{2})$`)

type envelope struct {
	Namespace  string
	Definition canonical.MessageDefinition
	Body       string
}

func detectEnvelope(data []byte) (envelope, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	depth := 0
	var result envelope

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return envelope{}, fmt.Errorf("%w: XML tokenization: %v", ErrInvalidEnvelope, err)
		}
		switch value := token.(type) {
		case xml.Directive:
			return envelope{}, fmt.Errorf("%w: directives such as DOCTYPE are not permitted", ErrUnsafeXML)
		case xml.ProcInst:
			if !strings.EqualFold(value.Target, "xml") || depth != 0 {
				return envelope{}, fmt.Errorf("%w: processing instruction %q is not permitted", ErrUnsafeXML, value.Target)
			}
		case xml.StartElement:
			depth++
			switch depth {
			case 1:
				if value.Name.Local != "Document" {
					return envelope{}, fmt.Errorf("%w: root element is %q, expected Document", ErrInvalidEnvelope, value.Name.Local)
				}
				if value.Name.Space == "" {
					return envelope{}, fmt.Errorf("%w: Document namespace is required", ErrInvalidEnvelope)
				}
				result.Namespace = value.Name.Space
				match := namespaceDefinitionPattern.FindStringSubmatch(result.Namespace)
				if len(match) != 2 {
					return envelope{}, fmt.Errorf("%w: namespace %q", ErrUnsupportedMessageDefinition, result.Namespace)
				}
				result.Definition = canonical.MessageDefinition(match[1])
			case 2:
				if result.Body != "" {
					return envelope{}, fmt.Errorf("%w: multiple document body elements", ErrInvalidEnvelope)
				}
				result.Body = value.Name.Local
			}
		case xml.EndElement:
			depth--
			if depth < 0 {
				return envelope{}, fmt.Errorf("%w: unbalanced XML", ErrInvalidEnvelope)
			}
		}
	}

	if depth != 0 || result.Namespace == "" || result.Body == "" {
		return envelope{}, fmt.Errorf("%w: incomplete Document envelope", ErrInvalidEnvelope)
	}
	return result, nil
}
