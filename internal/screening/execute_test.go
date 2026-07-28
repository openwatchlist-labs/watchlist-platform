package screening_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/adapters/iso20022"
	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screening"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningplan"
)

func TestExecuteBuildsMessageEvidenceBundle(t *testing.T) {
	message, executor := parseAndExecutor(t, "pacs008-basic.xml")
	bundle, err := executor.Execute(message)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.SchemaVersion != screening.EvidenceBundleSchemaVersion {
		t.Fatalf("schema version = %q", bundle.SchemaVersion)
	}
	if bundle.Summary.TotalElements != len(message.Elements) {
		t.Fatalf("summary total = %d, elements = %d", bundle.Summary.TotalElements, len(message.Elements))
	}
	if bundle.Summary.TransactionCount != 1 {
		t.Fatalf("transaction count = %d", bundle.Summary.TransactionCount)
	}
	if bundle.Summary.MatchEligibleElements == 0 {
		t.Fatal("expected match-eligible elements")
	}
	debtor := evidenceByRole(t, bundle, "debtor.name")
	if debtor.Resolution.TriggerPolicy != canonical.TriggerCandidateAlert {
		t.Fatalf("debtor trigger = %q", debtor.Resolution.TriggerPolicy)
	}
	if debtor.Resolution.EffectiveAction != screening.ActionCandidateLookup || !debtor.Resolution.EligibleForMatching {
		t.Fatalf("debtor execution = %#v", debtor.Resolution)
	}
	if !containsRoute(debtor, canonical.RouteNormalizedName) {
		t.Fatal("debtor name did not retain normalized_name route")
	}
	if !containsTarget(debtor, canonical.CandidateIndividual) || !containsTarget(debtor, canonical.CandidateOrganization) {
		t.Fatal("debtor target entity types are incomplete")
	}
	paymentID := evidenceByRole(t, bundle, "payment.instruction_id")
	if paymentID.Resolution.EffectiveAction != screening.ActionRetainOnly || paymentID.Resolution.EligibleForMatching {
		t.Fatalf("payment reference execution = %#v", paymentID.Resolution)
	}
	if err := screening.ValidateBundle(bundle); err != nil {
		t.Fatalf("bundle validation failed: %v", err)
	}
}

func TestExecuteIsDeterministic(t *testing.T) {
	message, executor := parseAndExecutor(t, "pacs008-basic.xml")
	first, err := executor.Execute(message)
	if err != nil {
		t.Fatal(err)
	}
	second, err := executor.Execute(message)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("same canonical message and plan produced different evidence")
	}
}

func TestExecuteRejectsMessagePlanDrift(t *testing.T) {
	message, executor := parseAndExecutor(t, "pacs008-basic.xml")
	message.ScreeningPlanChecksum = "sha256:tampered"
	_, err := executor.Execute(message)
	if !errors.Is(err, screening.ErrPlanMismatch) {
		t.Fatalf("expected ErrPlanMismatch, got %v", err)
	}
}

func TestExecuteRejectsElementAttachmentDrift(t *testing.T) {
	message, executor := parseAndExecutor(t, "pacs008-basic.xml")
	message.Elements[0].SemanticRole = "tampered.role"
	_, err := executor.Execute(message)
	if !errors.Is(err, screening.ErrPlanAttachmentMismatch) {
		t.Fatalf("expected ErrPlanAttachmentMismatch, got %v", err)
	}
}

func TestExecuteRejectsUnresolvedPath(t *testing.T) {
	message, executor := parseAndExecutor(t, "pacs008-basic.xml")
	message.Elements[0].NativePath = "/Document/FIToFICstmrCdtTrf/Unexpected"
	_, err := executor.Execute(message)
	if !errors.Is(err, screening.ErrPlanResolution) {
		t.Fatalf("expected ErrPlanResolution, got %v", err)
	}
}

func TestEmptyMatchingElementIsSkippedButPreserved(t *testing.T) {
	message, executor := parseAndExecutor(t, "pacs008-empty-name.xml")
	bundle, err := executor.Execute(message)
	if err != nil {
		t.Fatal(err)
	}
	debtor := evidenceByRole(t, bundle, "debtor.name")
	if debtor.Presence != canonical.PresenceEmpty {
		t.Fatalf("presence = %q", debtor.Presence)
	}
	if debtor.Resolution.EligibleForMatching || debtor.Resolution.EffectiveAction != screening.ActionSkipEmpty {
		t.Fatalf("empty debtor execution = %#v", debtor.Resolution)
	}
	if bundle.Summary.SkippedEmptyElements != 1 {
		t.Fatalf("skipped empty count = %d", bundle.Summary.SkippedEmptyElements)
	}
}

func TestInvalidMatchingElementIsSkippedButPreserved(t *testing.T) {
	message, executor := parseAndExecutor(t, "pacs008-basic.xml")
	var changed bool
	for index := range message.Elements {
		if message.Elements[index].SemanticRole == "debtor_agent.bic" {
			message.Elements[index].Presence = canonical.PresenceInvalid
			message.Elements[index].Warnings = []canonical.ParserWarning{{Code: "invalid_bic", Severity: canonical.SeverityWarning, Message: "test", Path: message.Elements[index].NativePath}}
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("debtor agent BIC not found")
	}
	bundle, err := executor.Execute(message)
	if err != nil {
		t.Fatal(err)
	}
	bic := evidenceByRole(t, bundle, "debtor_agent.bic")
	if bic.Resolution.EligibleForMatching || bic.Resolution.EffectiveAction != screening.ActionSkipInvalid {
		t.Fatalf("invalid BIC execution = %#v", bic.Resolution)
	}
	if bundle.Summary.SkippedInvalidElements != 1 {
		t.Fatalf("skipped invalid count = %d", bundle.Summary.SkippedInvalidElements)
	}
}

func TestEvidenceGoldenFiles(t *testing.T) {
	cases := []struct {
		fixture string
		kind    string
		golden  string
	}{
		{"pacs008-basic.xml", "canonical", "pacs008-basic.canonical.json"},
		{"pacs008-basic.xml", "evidence", "pacs008-basic.evidence.json"},
		{"pacs008-multi-transaction.xml", "evidence", "pacs008-multi-transaction.evidence.json"},
	}
	for _, test := range cases {
		t.Run(test.golden, func(t *testing.T) {
			message, executor := parseAndExecutor(t, test.fixture)
			var value any = message
			if test.kind == "evidence" {
				bundle, err := executor.Execute(message)
				if err != nil {
					t.Fatal(err)
				}
				value = bundle
			}
			actual, err := json.MarshalIndent(value, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			actual = append(actual, '\n')
			path := filepath.Join(repoRoot(t), "test", "golden", "iso20022", "pacs008", test.golden)
			expected, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(actual) != string(expected) {
				t.Fatalf("golden mismatch for %s; regenerate only after intentional contract review", path)
			}
		})
	}
}

func parseAndExecutor(t *testing.T, fixture string) (canonical.ParsedMessage, *screening.Executor) {
	t.Helper()
	planFile, err := os.Open(filepath.Join(repoRoot(t), "configs", "screening-plans", "iso20022-pacs008-cbprplus-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer planFile.Close()
	plan, err := screeningplan.Load(planFile)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := screeningplan.Compile(plan)
	if err != nil {
		t.Fatal(err)
	}
	parser, err := iso20022.NewParser(compiled)
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(filepath.Join(repoRoot(t), "test", "fixtures", "iso20022", "pacs008", fixture))
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	message, err := parser.Parse("fixture:"+fixture, input)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := screening.NewExecutor(compiled)
	if err != nil {
		t.Fatal(err)
	}
	return message, executor
}

func evidenceByRole(t *testing.T, bundle screening.EvidenceBundle, role canonical.SemanticRole) screening.ElementEvidence {
	t.Helper()
	for _, evidence := range bundle.Elements {
		if evidence.Resolution.SemanticRole == role {
			return evidence
		}
	}
	t.Fatalf("role %q not found", role)
	return screening.ElementEvidence{}
}

func containsRoute(evidence screening.ElementEvidence, route canonical.MatchRoute) bool {
	for _, candidate := range evidence.Resolution.MatchRoutes {
		if candidate == route {
			return true
		}
	}
	return false
}

func containsTarget(evidence screening.ElementEvidence, target canonical.CandidateType) bool {
	for _, candidate := range evidence.Resolution.TargetEntityTypes {
		if candidate == target {
			return true
		}
	}
	return false
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
