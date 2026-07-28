package iso20022

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/normalization"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningplan"
)

const (
	ParserVersion         = "iso20022-pacs008-parser/v0.1.0"
	DefaultMaximumPayload = int64(8 << 20)
)

var (
	bicPattern      = regexp.MustCompile(`^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$`)
	leiPattern      = regexp.MustCompile(`^[A-Z0-9]{20}$`)
	countryPattern  = regexp.MustCompile(`^[A-Z]{2}$`)
	ibanPattern     = regexp.MustCompile(`^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$`)
	amountPattern   = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?$`)
	currencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)
	uetrPattern     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
)

type Parser struct {
	plan     *screeningplan.CompiledPlan
	maxBytes int64
}

func NewParser(plan *screeningplan.CompiledPlan) (*Parser, error) {
	if plan == nil {
		return nil, fmt.Errorf("screening plan is required")
	}
	if !plan.Supports(Pacs00800108Definition) {
		return nil, fmt.Errorf("screening plan %s@%s does not support %s", plan.ID(), plan.Version(), Pacs00800108Definition)
	}
	return &Parser{plan: plan, maxBytes: DefaultMaximumPayload}, nil
}

func (parser *Parser) Parse(sourceReference string, reader io.Reader) (canonical.ParsedMessage, error) {
	if strings.TrimSpace(sourceReference) == "" {
		return canonical.ParsedMessage{}, fmt.Errorf("source payload reference is required")
	}
	data, err := io.ReadAll(io.LimitReader(reader, parser.maxBytes+1))
	if err != nil {
		return canonical.ParsedMessage{}, fmt.Errorf("read ISO 20022 payload: %w", err)
	}
	if int64(len(data)) > parser.maxBytes {
		return canonical.ParsedMessage{}, ErrPayloadTooLarge
	}

	envelope, err := detectEnvelope(data)
	if err != nil {
		return canonical.ParsedMessage{}, err
	}
	if envelope.Definition != Pacs00800108Definition || envelope.Namespace != Pacs00800108Namespace || envelope.Body != "FIToFICstmrCdtTrf" {
		return canonical.ParsedMessage{}, fmt.Errorf("%w: definition=%s body=%s namespace=%s", ErrUnsupportedMessageDefinition, envelope.Definition, envelope.Body, envelope.Namespace)
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	var document pacs008Document
	if err := decoder.Decode(&document); err != nil {
		return canonical.ParsedMessage{}, fmt.Errorf("decode %s: %w", envelope.Definition, err)
	}
	return parser.buildMessage(sourceReference, envelope, document)
}

func (parser *Parser) buildMessage(sourceReference string, envelope envelope, document pacs008Document) (canonical.ParsedMessage, error) {
	if document.Transfer.GroupHeader.MessageID == nil || strings.TrimSpace(document.Transfer.GroupHeader.MessageID.Value) == "" {
		return canonical.ParsedMessage{}, fmt.Errorf("%w: /Document/FIToFICstmrCdtTrf/GrpHdr/MsgId is required", ErrInvalidEnvelope)
	}
	messageID := strings.TrimSpace(document.Transfer.GroupHeader.MessageID.Value)
	builder := messageBuilder{
		parser:          parser,
		sourceReference: sourceReference,
		envelope:        envelope,
		messageID:       messageID,
	}

	builder.add(nil, "", "/Document/FIToFICstmrCdtTrf/GrpHdr/MsgId", 0, document.Transfer.GroupHeader.MessageID.Value, nil)
	if value := document.Transfer.GroupHeader.CreationDateTime; value != nil {
		builder.add(nil, "", "/Document/FIToFICstmrCdtTrf/GrpHdr/CreDtTm", 0, value.Value, nil)
	}
	if value := document.Transfer.GroupHeader.NumberOfTxs; value != nil {
		builder.add(nil, "", "/Document/FIToFICstmrCdtTrf/GrpHdr/NbOfTxs", 0, value.Value, nil)
		declared, err := strconv.Atoi(strings.TrimSpace(value.Value))
		if err == nil && declared != len(document.Transfer.Transactions) {
			builder.warnings = append(builder.warnings, canonical.ParserWarning{
				Code:     "transaction_count_mismatch",
				Severity: canonical.SeverityWarning,
				Message:  fmt.Sprintf("GrpHdr/NbOfTxs declares %d but %d CdtTrfTxInf elements were parsed", declared, len(document.Transfer.Transactions)),
				Path:     "/Document/FIToFICstmrCdtTrf/GrpHdr/NbOfTxs",
			})
		}
	}

	for index := range document.Transfer.Transactions {
		transaction := &document.Transfer.Transactions[index]
		transactionID := firstNonBlank(transaction.PaymentID.TransactionID, transaction.PaymentID.EndToEndID, transaction.PaymentID.InstructionID)
		prefix := fmt.Sprintf("/Document/FIToFICstmrCdtTrf/CdtTrfTxInf[%d]", index)
		builder.addPaymentIDs(index, transactionID, prefix, transaction.PaymentID)
		if transaction.InterbankSettlementAmt != nil {
			attributes := map[string]string{}
			if transaction.InterbankSettlementAmt.Currency != "" {
				attributes["Ccy"] = transaction.InterbankSettlementAmt.Currency
			}
			builder.add(indexPtr(index), transactionID, prefix+"/IntrBkSttlmAmt", 0, transaction.InterbankSettlementAmt.Value, attributes)
		}
		if transaction.InterbankSettlementDate != nil {
			builder.add(indexPtr(index), transactionID, prefix+"/IntrBkSttlmDt", 0, transaction.InterbankSettlementDate.Value, nil)
		}
		builder.addParty(index, transactionID, prefix+"/Dbtr", transaction.Debtor)
		builder.addParty(index, transactionID, prefix+"/UltmtDbtr", transaction.UltimateDebtor)
		builder.addAccount(index, transactionID, prefix+"/DbtrAcct", transaction.DebtorAccount)
		builder.addAgent(index, transactionID, prefix+"/DbtrAgt", transaction.DebtorAgent)
		builder.addAgent(index, transactionID, prefix+"/CdtrAgt", transaction.CreditorAgent)
		builder.addParty(index, transactionID, prefix+"/Cdtr", transaction.Creditor)
		builder.addParty(index, transactionID, prefix+"/UltmtCdtr", transaction.UltimateCreditor)
		builder.addAccount(index, transactionID, prefix+"/CdtrAcct", transaction.CreditorAccount)
		if transaction.Remittance != nil {
			for occurrence, value := range transaction.Remittance.Unstructured {
				path := fmt.Sprintf("%s/RmtInf/Ustrd[%d]", prefix, occurrence)
				builder.add(indexPtr(index), transactionID, path, occurrence, value, nil)
			}
		}
	}
	if builder.err != nil {
		return canonical.ParsedMessage{}, builder.err
	}

	message := canonical.ParsedMessage{
		SchemaVersion:          canonical.CanonicalSchemaVersion,
		MessageID:              messageID,
		MessageDefinition:      envelope.Definition,
		MessageNamespace:       envelope.Namespace,
		SourcePayloadReference: sourceReference,
		ParserVersion:          ParserVersion,
		ScreeningPlanID:        parser.plan.ID(),
		ScreeningPlanVersion:   parser.plan.Version(),
		ScreeningPlanChecksum:  parser.plan.Checksum(),
		Elements:               builder.elements,
		Warnings:               builder.warnings,
	}
	if err := canonical.ValidateMessage(message); err != nil {
		return canonical.ParsedMessage{}, err
	}
	return message, nil
}

type messageBuilder struct {
	parser          *Parser
	sourceReference string
	envelope        envelope
	messageID       string
	elements        []canonical.ScreenableElement
	warnings        []canonical.ParserWarning
	err             error
}

func (builder *messageBuilder) add(transactionIndex *int, transactionID, path string, occurrence int, value string, attributes map[string]string) {
	if builder.err != nil {
		return
	}
	entry, err := builder.parser.plan.Resolve(builder.envelope.Definition, path)
	if err != nil {
		builder.err = fmt.Errorf("%w: %s: %v", ErrPlanResolution, path, err)
		return
	}
	normalized, err := normalization.Normalize(entry.NormalizationProfile, value)
	if err != nil {
		builder.err = fmt.Errorf("normalize %s: %w", path, err)
		return
	}
	presence := canonical.PresencePresent
	if strings.TrimSpace(value) == "" {
		presence = canonical.PresenceEmpty
	}
	element := canonical.ScreenableElement{
		SchemaVersion:          canonical.ElementSchemaVersion,
		ElementID:              canonical.StableElementID(builder.sourceReference, builder.envelope.Definition, builder.messageID, transactionIndex, path, occurrence),
		MessageID:              builder.messageID,
		TransactionID:          transactionID,
		TransactionIndex:       transactionIndex,
		MessageDefinition:      builder.envelope.Definition,
		MessageNamespace:       builder.envelope.Namespace,
		NativePath:             path,
		Occurrence:             occurrence,
		Presence:               presence,
		OriginalValue:          value,
		NormalizedValue:        normalized,
		Attributes:             attributes,
		SourcePayloadReference: builder.sourceReference,
		ParserVersion:          ParserVersion,
	}
	builder.parser.plan.Apply(&element, entry)
	element.Warnings = validateElementValue(element)
	if len(element.Warnings) > 0 && element.Presence == canonical.PresencePresent {
		element.Presence = canonical.PresenceInvalid
	}
	builder.elements = append(builder.elements, element)
}

func (builder *messageBuilder) addPaymentIDs(index int, transactionID, prefix string, paymentID pacs008PaymentID) {
	values := []struct {
		name  string
		value *textValue
	}{
		{"InstrId", paymentID.InstructionID},
		{"EndToEndId", paymentID.EndToEndID},
		{"TxId", paymentID.TransactionID},
		{"UETR", paymentID.UETR},
	}
	for _, item := range values {
		if item.value != nil {
			builder.add(indexPtr(index), transactionID, prefix+"/PmtId/"+item.name, 0, item.value.Value, nil)
		}
	}
}

func (builder *messageBuilder) addParty(index int, transactionID, prefix string, party *partyIdentification) {
	if party == nil {
		return
	}
	if party.Name != nil {
		builder.add(indexPtr(index), transactionID, prefix+"/Nm", 0, party.Name.Value, nil)
	}
	if party.Identification != nil {
		if party.Identification.Organisation != nil && party.Identification.Organisation.LEI != nil {
			builder.add(indexPtr(index), transactionID, prefix+"/Id/OrgId/LEI", 0, party.Identification.Organisation.LEI.Value, nil)
		}
		if party.Identification.Private != nil && party.Identification.Private.Birth != nil && party.Identification.Private.Birth.BirthDate != nil {
			builder.add(indexPtr(index), transactionID, prefix+"/Id/PrvtId/DtAndPlcOfBirth/BirthDt", 0, party.Identification.Private.Birth.BirthDate.Value, nil)
		}
	}
	builder.addAddress(index, transactionID, prefix+"/PstlAdr", party.PostalAddress)
}

func (builder *messageBuilder) addAddress(index int, transactionID, prefix string, address *postalAddress) {
	if address == nil {
		return
	}
	if address.TownName != nil {
		builder.add(indexPtr(index), transactionID, prefix+"/TwnNm", 0, address.TownName.Value, nil)
	}
	if address.Country != nil {
		builder.add(indexPtr(index), transactionID, prefix+"/Ctry", 0, address.Country.Value, nil)
	}
	for occurrence, line := range address.AddressLines {
		path := fmt.Sprintf("%s/AdrLine[%d]", prefix, occurrence)
		builder.add(indexPtr(index), transactionID, path, occurrence, line, nil)
	}
}

func (builder *messageBuilder) addAccount(index int, transactionID, prefix string, account *cashAccount) {
	if account == nil {
		return
	}
	if account.Identification.IBAN != nil {
		builder.add(indexPtr(index), transactionID, prefix+"/Id/IBAN", 0, account.Identification.IBAN.Value, nil)
	}
	if account.Identification.Other != nil && account.Identification.Other.ID != nil {
		builder.add(indexPtr(index), transactionID, prefix+"/Id/Othr/Id", 0, account.Identification.Other.ID.Value, nil)
	}
}

func (builder *messageBuilder) addAgent(index int, transactionID, prefix string, agent *branchFinancialInstitution) {
	if agent == nil {
		return
	}
	institution := agent.Institution
	if institution.Name != nil {
		builder.add(indexPtr(index), transactionID, prefix+"/FinInstnId/Nm", 0, institution.Name.Value, nil)
	}
	if institution.BICFI != nil {
		builder.add(indexPtr(index), transactionID, prefix+"/FinInstnId/BICFI", 0, institution.BICFI.Value, nil)
	}
	if institution.LEI != nil {
		builder.add(indexPtr(index), transactionID, prefix+"/FinInstnId/LEI", 0, institution.LEI.Value, nil)
	}
	builder.addAddress(index, transactionID, prefix+"/FinInstnId/PstlAdr", institution.PostalAddress)
}

func validateElementValue(element canonical.ScreenableElement) []canonical.ParserWarning {
	if element.Presence == canonical.PresenceEmpty {
		return []canonical.ParserWarning{{Code: "empty_value", Severity: canonical.SeverityWarning, Message: "element is present but empty", Path: element.NativePath}}
	}
	value := element.NormalizedValue
	var warnings []canonical.ParserWarning
	addInvalid := func(code, message string) {
		warnings = append(warnings, canonical.ParserWarning{Code: code, Severity: canonical.SeverityWarning, Message: message, Path: element.NativePath})
	}
	switch element.ValueType {
	case "bic":
		if !bicPattern.MatchString(value) {
			addInvalid("invalid_bic", "BIC must contain four institution letters, two country letters, two location characters, and an optional three-character branch")
		}
	case "lei":
		if !leiPattern.MatchString(value) {
			addInvalid("invalid_lei", "LEI must be 20 uppercase alphanumeric characters")
		}
	case "country_code":
		if !countryPattern.MatchString(value) {
			addInvalid("invalid_country_code", "country code must be two uppercase letters")
		}
	case "iban":
		if !ibanPattern.MatchString(value) {
			addInvalid("invalid_iban", "IBAN must have a two-letter country prefix, check digits, and 11-30 additional alphanumeric characters")
		}
	case "uetr":
		if !uetrPattern.MatchString(value) {
			addInvalid("invalid_uetr", "UETR must be an RFC 4122 version 4 UUID")
		}
	case "amount":
		if !amountPattern.MatchString(value) {
			addInvalid("invalid_amount", "amount must be a non-negative decimal number")
		}
		if currency, ok := element.Attributes["Ccy"]; ok && !currencyPattern.MatchString(strings.ToUpper(currency)) {
			addInvalid("invalid_currency", "amount currency must be a three-letter uppercase code")
		}
	case "count":
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 {
			addInvalid("invalid_count", "count must be a non-negative integer")
		}
	case "date":
		if _, err := time.Parse("2006-01-02", value); err != nil {
			addInvalid("invalid_date", "date must use YYYY-MM-DD")
		}
	case "datetime":
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			addInvalid("invalid_datetime", "datetime must use RFC 3339")
		}
	}
	return warnings
}

func firstNonBlank(values ...*textValue) string {
	for _, value := range values {
		if value != nil && strings.TrimSpace(value.Value) != "" {
			return strings.TrimSpace(value.Value)
		}
	}
	return ""
}

func indexPtr(value int) *int {
	copy := value
	return &copy
}

func IsUnsupported(err error) bool {
	return errors.Is(err, ErrUnsupportedMessageDefinition)
}
