package assistancerag

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"
)

func LoadManifest(path string) (CorpusManifest, error) {
	var manifest CorpusManifest
	if err := ReadStrictJSON(path, &manifest); err != nil {
		return manifest, err
	}
	if manifest.SchemaVersion != CorpusManifestSchemaV1 {
		return manifest, fmt.Errorf("unsupported manifest schema %q", manifest.SchemaVersion)
	}
	if strings.TrimSpace(manifest.CorpusID) == "" || strings.TrimSpace(manifest.Version) == "" {
		return manifest, errors.New("corpus_id and version are required")
	}
	if _, err := NormalizeTime(manifest.BuiltAt); err != nil {
		return manifest, err
	}
	if len(manifest.Documents) == 0 {
		return manifest, errors.New("manifest documents are required")
	}
	seen := map[string]struct{}{}
	for i, doc := range manifest.Documents {
		if doc.DocumentID == "" || doc.TenantID == "" || doc.Kind == "" || doc.Title == "" || doc.SourceRef == "" || strings.TrimSpace(doc.Text) == "" {
			return manifest, fmt.Errorf("document %d is incomplete", i)
		}
		if _, ok := seen[doc.DocumentID]; ok {
			return manifest, fmt.Errorf("duplicate document_id %q", doc.DocumentID)
		}
		seen[doc.DocumentID] = struct{}{}
		if doc.Kind != "policy" && doc.Kind != "guidance" && doc.Kind != "prior_case" {
			return manifest, fmt.Errorf("unsupported document kind %q", doc.Kind)
		}
		if doc.Kind == "prior_case" && doc.TenantID == "*" {
			return manifest, errors.New("prior_case documents must be tenant scoped")
		}
		if _, err := NormalizeTime(doc.EffectiveAt); err != nil {
			return manifest, fmt.Errorf("document %s: %w", doc.DocumentID, err)
		}
	}
	return manifest, nil
}

func CompileSnapshot(manifest CorpusManifest) (CorpusSnapshot, error) {
	manifestCopy := manifest
	sort.Slice(manifestCopy.Documents, func(i, j int) bool {
		return manifestCopy.Documents[i].DocumentID < manifestCopy.Documents[j].DocumentID
	})
	manifestSHA, err := HashObject(manifestCopy)
	if err != nil {
		return CorpusSnapshot{}, err
	}
	passages := make([]Passage, 0)
	for _, doc := range manifestCopy.Documents {
		chunks := splitPassages(doc.Text)
		for i, text := range chunks {
			identity := fmt.Sprintf("%s:%04d:%s", doc.DocumentID, i+1, SHA256Bytes([]byte(text)))
			passages = append(passages, Passage{
				PassageID: "passage_" + HashString(identity)[:24], DocumentID: doc.DocumentID, TenantID: doc.TenantID,
				Kind: doc.Kind, Title: doc.Title, SourceRef: doc.SourceRef, EffectiveAt: doc.EffectiveAt,
				Ordinal: i + 1, Text: text, TextSHA256: SHA256Bytes([]byte(text)),
			})
		}
	}
	sort.Slice(passages, func(i, j int) bool { return passages[i].PassageID < passages[j].PassageID })
	snapshot := CorpusSnapshot{SchemaVersion: CorpusSnapshotSchemaV1, CorpusID: manifest.CorpusID, Version: manifest.Version, BuiltAt: manifest.BuiltAt, ManifestSHA256: manifestSHA, PassageCount: len(passages), Passages: passages}
	hashCopy := snapshot
	hashCopy.SnapshotSHA256 = ""
	snapshot.SnapshotSHA256, err = HashObject(hashCopy)
	if err != nil {
		return CorpusSnapshot{}, err
	}
	return snapshot, nil
}

func splitPassages(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	parts := strings.Split(text, "\n\n")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Join(strings.Fields(part), " ")
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func LoadSnapshot(path string) (CorpusSnapshot, error) {
	var snapshot CorpusSnapshot
	if err := ReadStrictJSON(path, &snapshot); err != nil {
		return snapshot, err
	}
	if err := VerifySnapshot(snapshot); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func VerifySnapshot(snapshot CorpusSnapshot) error {
	if snapshot.SchemaVersion != CorpusSnapshotSchemaV1 {
		return fmt.Errorf("unsupported snapshot schema %q", snapshot.SchemaVersion)
	}
	if snapshot.PassageCount != len(snapshot.Passages) {
		return errors.New("passage count mismatch")
	}
	seen := map[string]struct{}{}
	for _, p := range snapshot.Passages {
		if p.PassageID == "" || p.DocumentID == "" || p.TenantID == "" || p.Text == "" {
			return errors.New("incomplete passage")
		}
		if _, ok := seen[p.PassageID]; ok {
			return fmt.Errorf("duplicate passage %q", p.PassageID)
		}
		seen[p.PassageID] = struct{}{}
		if SHA256Bytes([]byte(p.Text)) != p.TextSHA256 {
			return fmt.Errorf("passage %s checksum mismatch", p.PassageID)
		}
	}
	hashCopy := snapshot
	expected := hashCopy.SnapshotSHA256
	hashCopy.SnapshotSHA256 = ""
	actual, err := HashObject(hashCopy)
	if err != nil {
		return err
	}
	if expected != actual {
		return errors.New("snapshot checksum mismatch")
	}
	return nil
}

func WriteSnapshot(path string, snapshot CorpusSnapshot) error {
	return WriteJSONAtomic(path, snapshot, 0o644)
}

func Query(snapshot CorpusSnapshot, query RetrievalQuery) (RetrievalPackage, error) {
	if err := VerifySnapshot(snapshot); err != nil {
		return RetrievalPackage{}, err
	}
	if strings.TrimSpace(query.TenantID) == "" {
		return RetrievalPackage{}, errors.New("tenant_id is required")
	}
	terms := normalizeTerms(query.Terms)
	if len(terms) == 0 {
		return RetrievalPackage{}, errors.New("query terms are required")
	}
	if query.TopK <= 0 {
		query.TopK = 6
	}
	if query.TopK > 20 {
		return RetrievalPackage{}, errors.New("top_k exceeds 20")
	}
	type scored struct {
		passage Passage
		score   int
		matches []string
	}
	items := make([]scored, 0)
	for _, p := range snapshot.Passages {
		if p.TenantID != "*" && p.TenantID != query.TenantID {
			continue
		}
		titleTokens := tokenSet(p.Title)
		textTokens := tokenSet(p.Text)
		score := 0
		matches := make([]string, 0)
		for _, term := range terms {
			_, titleMatch := titleTokens[term]
			_, textMatch := textTokens[term]
			if titleMatch {
				score += 4
			}
			if textMatch {
				score += 2
			}
			if titleMatch || textMatch {
				matches = append(matches, term)
			}
		}
		if score > 0 {
			items = append(items, scored{p, score, matches})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		return items[i].passage.PassageID < items[j].passage.PassageID
	})
	if len(items) > query.TopK {
		items = items[:query.TopK]
	}
	result := RetrievalPackage{SchemaVersion: RetrievalSchemaV1, CorpusID: snapshot.CorpusID, CorpusVersion: snapshot.Version, SnapshotSHA256: snapshot.SnapshotSHA256, TenantID: query.TenantID, QueryTerms: terms}
	for _, item := range items {
		p := item.passage
		result.Passages = append(result.Passages, RetrievedPassage{PassageID: p.PassageID, DocumentID: p.DocumentID, Kind: p.Kind, Title: p.Title, SourceRef: p.SourceRef, EffectiveAt: p.EffectiveAt, Text: p.Text, TextSHA256: p.TextSHA256, Score: item.score, MatchTerms: SortedUnique(item.matches)})
	}
	hashCopy := result
	hashCopy.PackageSHA256 = ""
	result.PackageSHA256, _ = HashObject(hashCopy)
	return result, nil
}

func normalizeTerms(values []string) []string {
	var terms []string
	for _, value := range values {
		for token := range tokenSet(value) {
			if len(token) >= 2 {
				terms = append(terms, token)
			}
		}
	}
	return SortedUnique(terms)
}

func tokenSet(value string) map[string]struct{} {
	value = strings.ToUpper(value)
	var b strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	out := map[string]struct{}{}
	for _, token := range strings.Fields(b.String()) {
		out[token] = struct{}{}
	}
	return out
}

func DecodeSnapshot(raw []byte) (CorpusSnapshot, error) {
	var s CorpusSnapshot
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, err
	}
	return s, VerifySnapshot(s)
}

func ReadSnapshotFile(path string) ([]byte, error) { return os.ReadFile(path) }
