package iso20022

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningplan"
)

func TestParsePacs008Basic(t *testing.T) {
	parser := testParser(t)
	message := parseFixture(t, parser, "pacs008-basic.xml")

	if message.MessageID != "OWP-PACS008-0001" {
		t.Fatalf("message id = %q", message.MessageID)
	}
	if message.MessageDefinition != Pacs00800108Definition {
		t.Fatalf("definition = %q", message.MessageDefinition)
	}
	if len(message.Elements) < 30 {
		t.Fatalf("elements = %d, expected at least 30", len(message.Elements))
	}

	debtorName := requireRole(t, message, "debtor.name")
	if debtorName.OriginalValue != "Acme Imports LLC" || debtorName.NormalizedValue != "ACME IMPORTS LLC" {
		t.Fatalf("unexpected debtor name: %#v", debtorName)
	}
	if debtorName.Screening.TriggerPolicy != canonical.TriggerCandidateAlert || !hasRoute(debtorName, canonical.RouteNormalizedName) {
		t.Fatalf("debtor name directive = %#v", debtorName.Screening)
	}

	debtorBIC := requireRole(t, message, "debtor_agent.bic")
	if !hasRoute(debtorBIC, canonical.RouteExactBIC) {
		t.Fatalf("debtor BIC routes = %v", debtorBIC.Screening.MatchRoutes)
	}

	creditorAccount := requireRole(t, message, "creditor_account.iban")
	if creditorAccount.Screening.TriggerPolicy != canonical.TriggerSupportingEvidence || !hasRoute(creditorAccount, canonical.RouteExactAccount) {
		t.Fatalf("creditor account directive = %#v", creditorAccount.Screening)
	}

	country := requireRole(t, message, "creditor.address.country")
	if country.NormalizedValue != "DE" || !hasRoute(country, canonical.RouteJurisdictionPolicy) {
		t.Fatalf("country element = %#v", country)
	}

	remittance := elementsByRole(message, "remittance.unstructured")
	if len(remittance) != 2 {
		t.Fatalf("remittance count = %d", len(remittance))
	}
	if remittance[0].NativePath != "/Document/FIToFICstmrCdtTrf/CdtTrfTxInf[0]/RmtInf/Ustrd[0]" || remittance[1].Occurrence != 1 {
		t.Fatalf("remittance paths/occurrences incorrect: %#v", remittance)
	}

	for _, role := range []canonical.SemanticRole{
		"payment.instruction_id",
		"payment.end_to_end_id",
		"payment.transaction_id",
		"payment.uetr",
		"payment.interbank_settlement_amount",
		"payment.interbank_settlement_date",
	} {
		element := requireRole(t, message, role)
		if element.Screening.TriggerPolicy != canonical.TriggerRetainOnly || len(element.Screening.MatchRoutes) != 0 {
			t.Fatalf("%s must be retain-only, got %#v", role, element.Screening)
		}
	}

	for _, element := range message.Elements {
		if element.Presence == canonical.PresenceInvalid {
			t.Fatalf("basic fixture produced invalid element %s: %v", element.NativePath, element.Warnings)
		}
	}
}

func TestParsePacs008IsDeterministic(t *testing.T) {
	parser := testParser(t)
	first := parseFixture(t, parser, "pacs008-basic.xml")
	second := parseFixture(t, parser, "pacs008-basic.xml")
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstJSON, secondJSON) {
		t.Fatal("same source and plan did not produce deterministic canonical JSON")
	}
}

func TestParsePacs008MultiTransactionIsolation(t *testing.T) {
	message := parseFixture(t, testParser(t), "pacs008-multi-transaction.xml")
	seen := map[int]map[string]bool{}
	for _, element := range message.Elements {
		if element.TransactionIndex == nil {
			continue
		}
		index := *element.TransactionIndex
		if seen[index] == nil {
			seen[index] = map[string]bool{}
		}
		seen[index][element.TransactionID] = true
		if index == 0 && element.NativePath == "/Document/FIToFICstmrCdtTrf/CdtTrfTxInf[1]/Dbtr/Nm" {
			t.Fatal("transaction index leaked across native paths")
		}
	}
	if !seen[0]["TX-MULTI-1"] || !seen[1]["TX-MULTI-2"] {
		t.Fatalf("transaction IDs by index = %#v", seen)
	}
	remittance := elementsByRole(message, "remittance.unstructured")
	if len(remittance) != 3 {
		t.Fatalf("remittance count = %d, want 3", len(remittance))
	}
}

func TestParsePacs008PreservesPresentEmpty(t *testing.T) {
	message := parseFixture(t, testParser(t), "pacs008-empty-name.xml")
	debtor := requireRole(t, message, "debtor.name")
	if debtor.Presence != canonical.PresenceEmpty {
		t.Fatalf("presence = %q, want empty", debtor.Presence)
	}
	if len(debtor.Warnings) != 1 || debtor.Warnings[0].Code != "empty_value" {
		t.Fatalf("warnings = %#v", debtor.Warnings)
	}
}

func TestParseRejectsUnsafeAndUnsupportedXML(t *testing.T) {
	parser := testParser(t)
	tests := []struct {
		fixture string
		want    error
	}{
		{"pacs008-unsafe-doctype.xml", ErrUnsafeXML},
		{"pacs008-unsupported-version.xml", ErrUnsupportedMessageDefinition},
		{"pacs008-malformed.xml", ErrInvalidEnvelope},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			file, err := os.Open(filepath.Join(fixtureDir(t), test.fixture))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			_, err = parser.Parse("fixture:"+test.fixture, file)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want errors.Is(%v)", err, test.want)
			}
		})
	}
}

func testParser(t *testing.T) *Parser {
	t.Helper()
	file, err := os.Open(filepath.Join(repoRoot(t), "configs", "screening-plans", "iso20022-pacs008-cbprplus-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	plan, err := screeningplan.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := screeningplan.Compile(plan)
	if err != nil {
		t.Fatal(err)
	}
	parser, err := NewParser(compiled)
	if err != nil {
		t.Fatal(err)
	}
	return parser
}

func parseFixture(t *testing.T, parser *Parser, name string) canonical.ParsedMessage {
	t.Helper()
	file, err := os.Open(filepath.Join(fixtureDir(t), name))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	message, err := parser.Parse("fixture:"+name, file)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func requireRole(t *testing.T, message canonical.ParsedMessage, role canonical.SemanticRole) canonical.ScreenableElement {
	t.Helper()
	elements := elementsByRole(message, role)
	if len(elements) == 0 {
		t.Fatalf("semantic role %q not found", role)
	}
	return elements[0]
}

func elementsByRole(message canonical.ParsedMessage, role canonical.SemanticRole) []canonical.ScreenableElement {
	var result []canonical.ScreenableElement
	for _, element := range message.Elements {
		if element.SemanticRole == role {
			result = append(result, element)
		}
	}
	return result
}

func hasRoute(element canonical.ScreenableElement, route canonical.MatchRoute) bool {
	for _, candidate := range element.Screening.MatchRoutes {
		if candidate == route {
			return true
		}
	}
	return false
}

func fixtureDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "test", "fixtures", "iso20022", "pacs008")
}

func repoRoot(t *testing.T) string {
	t.Helper()
	current, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("repository root not found")
		}
		current = parent
	}
}
