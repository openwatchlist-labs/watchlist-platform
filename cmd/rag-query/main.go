package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/policyengine"
	"github.com/openwatchlist-labs/watchlist-platform/internal/rag"
)

func main() {
	snapshotPath := flag.String("snapshot", "", "path to immutable corpus snapshot")
	policyPath := flag.String("retrieval-policy", "", "path to retrieval policy JSON")
	queryPath := flag.String("query", "", "path to structured retrieval query JSON")
	decisionBatchPath := flag.String("decision-batch", "", "path to policy decision batch JSON")
	caseID := flag.String("case-id", "", "observation case ID when adapting a decision")
	tenantID := flag.String("tenant-id", "tenant-a", "tenant scope for decision adaptation")
	effectiveAt := flag.String("effective-at", "2026-07-14T00:00:00Z", "effective timestamp for decision adaptation")
	flag.Parse()
	if *snapshotPath == "" || *policyPath == "" {
		fatalf("--snapshot and --retrieval-policy are required")
	}
	if (*queryPath == "") == (*decisionBatchPath == "") {
		fatalf("provide exactly one of --query or --decision-batch")
	}
	snapshot, err := rag.LoadSnapshot(*snapshotPath)
	if err != nil {
		fatalf("load snapshot: %v", err)
	}
	policy, err := rag.LoadPolicy(*policyPath)
	if err != nil {
		fatalf("load retrieval policy: %v", err)
	}
	var query rag.RetrievalQuery
	if *queryPath != "" {
		query, err = rag.LoadQuery(*queryPath)
	} else {
		if *caseID == "" {
			fatalf("--case-id is required with --decision-batch")
		}
		decision, readErr := readDecision(*decisionBatchPath, *caseID)
		if readErr != nil {
			fatalf("read decision: %v", readErr)
		}
		query, err = rag.QueryFromDecision(decision, *tenantID, *effectiveAt)
	}
	if err != nil {
		fatalf("build query: %v", err)
	}
	retriever, err := rag.NewRetriever(snapshot, policy)
	if err != nil {
		fatalf("create retriever: %v", err)
	}
	pkg, err := retriever.Retrieve(query)
	if err != nil {
		fatalf("retrieve: %v", err)
	}
	writeJSON(pkg)
}

func readDecision(path, caseID string) (policyengine.Decision, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return policyengine.Decision{}, err
	}
	var batch policyengine.DecisionBatch
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&batch); err != nil {
		return policyengine.Decision{}, err
	}
	if err := policyengine.ValidateDecisionBatch(batch); err != nil {
		return policyengine.Decision{}, err
	}
	for _, decision := range batch.Decisions {
		if decision.Classification.Observation.CaseID == caseID {
			return decision, nil
		}
	}
	return policyengine.Decision{}, fmt.Errorf("case_id %q not found", caseID)
}

func writeJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		fatalf("encode output: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
