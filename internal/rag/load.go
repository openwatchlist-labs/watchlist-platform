package rag

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func decodeStrict(path string, output any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if decoder.More() {
		return fmt.Errorf("unexpected trailing JSON content")
	}
	return nil
}

func LoadManifest(path string) (CorpusManifest, error) {
	var manifest CorpusManifest
	if err := decodeStrict(path, &manifest); err != nil {
		return CorpusManifest{}, err
	}
	if err := ValidateManifest(manifest); err != nil {
		return CorpusManifest{}, err
	}
	return manifest, nil
}

func LoadSnapshot(path string) (CorpusSnapshot, error) {
	var snapshot CorpusSnapshot
	if err := decodeStrict(path, &snapshot); err != nil {
		return CorpusSnapshot{}, err
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		return CorpusSnapshot{}, err
	}
	return snapshot, nil
}

func LoadPolicy(path string) (RetrievalPolicy, error) {
	var policy RetrievalPolicy
	if err := decodeStrict(path, &policy); err != nil {
		return RetrievalPolicy{}, err
	}
	if err := ValidatePolicy(policy); err != nil {
		return RetrievalPolicy{}, err
	}
	return policy, nil
}

func LoadQuery(path string) (RetrievalQuery, error) {
	var query RetrievalQuery
	if err := decodeStrict(path, &query); err != nil {
		return RetrievalQuery{}, err
	}
	if query.QueryID == "" {
		query.QueryID = stableQueryID(query)
	}
	if err := ValidateQuery(query); err != nil {
		return RetrievalQuery{}, err
	}
	return query, nil
}

func LoadCitationPackage(path string) (CitationPackage, error) {
	var pkg CitationPackage
	if err := decodeStrict(path, &pkg); err != nil {
		return CitationPackage{}, err
	}
	if err := ValidateCitationPackage(pkg); err != nil {
		return CitationPackage{}, err
	}
	return pkg, nil
}

func BuildSnapshot(manifestPath string, manifest CorpusManifest) (CorpusSnapshot, error) {
	base := filepath.Dir(manifestPath)
	snapshot := CorpusSnapshot{
		SchemaVersion:  CorpusSnapshotSchema,
		CorpusID:       manifest.CorpusID,
		CorpusVersion:  manifest.CorpusVersion,
		SnapshotAt:     manifest.SnapshotAt,
		CorpusChecksum: manifest.CorpusChecksum,
		Documents:      make([]Document, 0, len(manifest.Documents)),
	}
	for _, spec := range manifest.Documents {
		content, err := os.ReadFile(filepath.Join(base, filepath.Clean(spec.Path)))
		if err != nil {
			return CorpusSnapshot{}, fmt.Errorf("read %s: %w", spec.Path, err)
		}
		doc := Document{Spec: spec, ContentChecksum: checksumBytes(content)}
		doc.Chunks = chunkMarkdown(spec.SourceID, string(content))
		if len(doc.Chunks) == 0 {
			return CorpusSnapshot{}, fmt.Errorf("document %s produced no chunks", spec.SourceID)
		}
		snapshot.Documents = append(snapshot.Documents, doc)
	}
	sort.Slice(snapshot.Documents, func(i, j int) bool { return snapshot.Documents[i].Spec.SourceID < snapshot.Documents[j].Spec.SourceID })
	snapshot.SnapshotID = stableSnapshotID(snapshot)
	if err := ValidateSnapshot(snapshot); err != nil {
		return CorpusSnapshot{}, err
	}
	return snapshot, nil
}

func checksumBytes(data []byte) string {
	return checksumJSON(string(data))
}

func chunkMarkdown(sourceID, content string) []Chunk {
	scanner := bufio.NewScanner(strings.NewReader(content))
	headings := []string{}
	paragraph := []string{}
	chunks := []Chunk{}
	block := 0
	flush := func() {
		text := strings.TrimSpace(strings.Join(paragraph, "\n"))
		paragraph = nil
		if text == "" {
			return
		}
		block++
		locator := fmt.Sprintf("block:%d", block)
		if len(headings) > 0 {
			locator = "section:" + strings.Join(headings, " > ") + fmt.Sprintf("#block:%d", block)
		}
		indicators := instructionIndicators(text)
		chunk := Chunk{
			SourceID:              sourceID,
			HeadingPath:           append([]string(nil), headings...),
			Locator:               locator,
			Text:                  text,
			ContentChecksum:       checksumJSON(text),
			Tokens:                tokenize(strings.Join(headings, " ") + " " + text),
			InstructionLike:       len(indicators) > 0,
			InstructionIndicators: indicators,
		}
		chunk.ChunkID = hashJSON("rag_chunk_", chunk)
		chunks = append(chunks, chunk)
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			flush()
			level := 0
			for level < len(line) && line[level] == '#' {
				level++
			}
			title := strings.TrimSpace(line[level:])
			if level > 0 && title != "" {
				if level <= len(headings) {
					headings = headings[:level-1]
				}
				for len(headings) < level-1 {
					headings = append(headings, "")
				}
				headings = append(headings, title)
			}
			continue
		}
		if line == "" {
			flush()
			continue
		}
		paragraph = append(paragraph, line)
	}
	flush()
	return chunks
}
