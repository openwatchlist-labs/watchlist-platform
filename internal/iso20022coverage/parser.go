package iso20022coverage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"
)

const (
	maxXMLBytes = 16 << 20
	maxDepth    = 128
	maxNodes    = 200000
)

type node struct {
	Name     xml.Name
	Text     string
	Children []*node
	Parent   *node
	Index    int
}

func Parse(matrix *Matrix, sourceRef string, data []byte) (*EvidenceEnvelope, error) {
	if matrix == nil {
		return nil, errors.New("matrix is required")
	}
	if strings.TrimSpace(sourceRef) == "" {
		return nil, errors.New("source_ref is required")
	}
	if len(data) == 0 || len(data) > maxXMLBytes {
		return nil, fmt.Errorf("XML size must be between 1 and %d bytes", maxXMLBytes)
	}
	upper := bytes.ToUpper(data)
	if bytes.Contains(upper, []byte("<!DOCTYPE")) || bytes.Contains(upper, []byte("<!ENTITY")) {
		return nil, errors.New("XML directives and entities are prohibited")
	}
	root, err := parseTree(data)
	if err != nil {
		return nil, err
	}
	profile, businessRoot, err := detectProfile(matrix, root)
	if err != nil {
		return nil, err
	}
	sourceSum := sha256.Sum256(data)
	sourceSHA := hex.EncodeToString(sourceSum[:])
	txIndex := transactionIndexes(businessRoot, profile.TransactionContainers)
	elements := collectElements(businessRoot, txIndex, sourceSHA, profile.ProfileID)
	screenable := 0
	maxTx := 0
	for _, e := range elements {
		if e.MatchEligible {
			screenable++
		}
		if e.TransactionIndex > maxTx {
			maxTx = e.TransactionIndex
		}
	}
	warnings := []ValidationNotice{}
	if screenable == 0 && profile.SupportLevel == "end_to_end" {
		warnings = append(warnings, ValidationNotice{Code: "NO_SCREENABLE_ELEMENTS", Detail: "supported message contained no configured screenable values"})
	}
	env := EvidenceEnvelope{
		SchemaVersion:       "openwatchlist.iso20022-family-evidence.v1",
		SourceRef:           sourceRef,
		SourceSHA256:        sourceSHA,
		MatrixID:            matrix.MatrixID,
		MatrixVersion:       matrix.Version,
		MatrixSHA256:        matrix.SHA256,
		ProfileID:           profile.ProfileID,
		MessageDefinitionID: profile.MessageDefinitionID,
		Variant:             profile.Variant,
		Namespace:           businessRoot.Name.Space,
		RootElement:         businessRoot.Name.Local,
		SupportLevel:        profile.SupportLevel,
		TransactionCount:    maxTx,
		ElementCount:        len(elements),
		ScreenableCount:     screenable,
		Elements:            elements,
		Warnings:            warnings,
	}
	if env.TransactionCount == 0 {
		env.TransactionCount = 1
	}
	env.EnvelopeSHA256 = hashStruct(env, func(v *EvidenceEnvelope) { v.EnvelopeSHA256 = "" })
	return &env, nil
}

func parseTree(data []byte) (*node, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	var stack []*node
	var root *node
	nodes := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return nil, errors.New("XML directives are prohibited")
		case xml.StartElement:
			if len(stack) >= maxDepth {
				return nil, fmt.Errorf("XML depth exceeds %d", maxDepth)
			}
			nodes++
			if nodes > maxNodes {
				return nil, fmt.Errorf("XML node count exceeds %d", maxNodes)
			}
			n := &node{Name: t.Name, Index: 1}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				n.Parent = p
				for _, sibling := range p.Children {
					if sibling.Name.Local == n.Name.Local {
						n.Index++
					}
				}
				p.Children = append(p.Children, n)
			} else if root == nil {
				root = n
			} else {
				return nil, errors.New("multiple XML roots")
			}
			stack = append(stack, n)
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(t)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("unexpected XML end element")
			}
			n := stack[len(stack)-1]
			n.Text = strings.TrimSpace(strings.Join(strings.Fields(n.Text), " "))
			stack = stack[:len(stack)-1]
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, errors.New("incomplete XML document")
	}
	return root, nil
}

func detectProfile(matrix *Matrix, root *node) (FamilyProfile, *node, error) {
	var candidates []*node
	walk(root, func(n *node) {
		for _, f := range matrix.Families {
			if n.Name.Local == f.RootElement && n.Name.Space == f.Namespace {
				candidates = append(candidates, n)
				return
			}
		}
	})
	if len(candidates) == 0 {
		return FamilyProfile{}, nil, fmt.Errorf("unsupported ISO 20022 namespace/root %q/%q", root.Name.Space, root.Name.Local)
	}
	for _, n := range candidates {
		var fallback *FamilyProfile
		for i := range matrix.Families {
			f := &matrix.Families[i]
			if f.Namespace != n.Name.Space || f.RootElement != n.Name.Local {
				continue
			}
			if f.ContainsElement == "" {
				fallback = f
				continue
			}
			if containsLocal(n, f.ContainsElement) {
				return *f, n, nil
			}
		}
		if fallback != nil {
			return *fallback, n, nil
		}
	}
	return FamilyProfile{}, nil, errors.New("ISO 20022 profile discriminator did not match")
}

func transactionIndexes(root *node, containers []string) map[*node]int {
	set := map[string]bool{}
	for _, c := range containers {
		set[c] = true
	}
	out := map[*node]int{}
	idx := 0
	walk(root, func(n *node) {
		if set[n.Name.Local] {
			idx++
			out[n] = idx
		}
	})
	return out
}

func collectElements(root *node, tx map[*node]int, sourceSHA, profileID string) []EvidenceElement {
	var out []EvidenceElement
	walk(root, func(n *node) {
		if len(n.Children) != 0 || n.Text == "" {
			return
		}
		kind, action, eligible := classify(n)
		if kind == "" {
			return
		}
		txIdx := nearestTransaction(n, tx)
		if txIdx == 0 {
			txIdx = 1
		}
		role := semanticRole(n)
		path := nodePath(n)
		normalized := normalize(kind, n.Text)
		id := shortHash(sourceSHA, profileID, path, role, kind, n.Text)
		out = append(out, EvidenceElement{
			ElementID:        "isoel_" + id,
			TransactionIndex: txIdx,
			FieldPath:        path,
			SemanticRole:     role,
			Kind:             kind,
			Value:            n.Text,
			NormalizedValue:  normalized,
			Action:           action,
			MatchEligible:    eligible,
		})
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TransactionIndex != out[j].TransactionIndex {
			return out[i].TransactionIndex < out[j].TransactionIndex
		}
		if out[i].FieldPath != out[j].FieldPath {
			return out[i].FieldPath < out[j].FieldPath
		}
		return out[i].ElementID < out[j].ElementID
	})
	return out
}

func classify(n *node) (string, string, bool) {
	local := n.Name.Local
	path := nodePath(n)
	switch local {
	case "Nm":
		return "party_name", "fuzzy_name", true
	case "BIC", "BICFI":
		return "bic", "exact_identifier", true
	case "LEI":
		return "lei", "exact_identifier", true
	case "IBAN":
		return "iban", "exact_identifier", true
	case "Ctry", "CtryOfRes":
		return "country", "exact_country", true
	case "AdrLine", "StrtNm", "BldgNb", "PstCd", "TwnNm", "CtrySubDvsn":
		return "address", "contextual_text", true
	case "Ustrd", "AddtlRmtInf":
		return "remittance", "contextual_text", true
	case "DtOfBirth":
		return "date_of_birth", "exact_date", true
	case "InstdAmt", "IntrBkSttlmAmt", "Amt":
		return "amount", "evidence_only", false
	case "CreDtTm", "IntrBkSttlmDt", "ReqdExctnDt", "BookgDt", "ValDt":
		return "date", "evidence_only", false
	case "MsgId", "BizMsgIdr", "InstrId", "EndToEndId", "TxId", "UETR", "OrgnlMsgId", "OrgnlInstrId", "OrgnlEndToEndId", "OrgnlTxId", "CxlId":
		return "reference", "evidence_only", false
	case "Cd", "Prtry":
		if strings.Contains(path, "/Rsn") || strings.Contains(path, "StsRsn") {
			return "status_reason", "evidence_only", false
		}
	case "AddtlInf":
		return "status_information", "evidence_only", false
	case "Id":
		if identifierContext(n) {
			return "other_identifier", "exact_identifier", true
		}
		return "reference", "evidence_only", false
	}
	return "", "", false
}

func identifierContext(n *node) bool {
	for p := n.Parent; p != nil; p = p.Parent {
		switch p.Name.Local {
		case "Othr", "OrgId", "PrvtId", "Acct", "Id":
			return true
		case "Dbtr", "Cdtr", "UltmtDbtr", "UltmtCdtr", "InitgPty", "Pty":
			return false
		}
	}
	return false
}

func semanticRole(n *node) string {
	roles := map[string]string{
		"Dbtr": "debtor", "Cdtr": "creditor", "UltmtDbtr": "ultimate_debtor", "UltmtCdtr": "ultimate_creditor",
		"InitgPty": "initiating_party", "DbtrAgt": "debtor_agent", "CdtrAgt": "creditor_agent",
		"InstgAgt": "instructing_agent", "InstdAgt": "instructed_agent", "IntrmyAgt1": "intermediary_agent_1",
		"IntrmyAgt2": "intermediary_agent_2", "IntrmyAgt3": "intermediary_agent_3", "OrgnlDbtr": "original_debtor",
		"OrgnlCdtr": "original_creditor", "RtrChain": "return_chain", "Case": "investigation_case",
		"RmtInf": "remittance", "OrgnlTxRef": "original_transaction", "Ntry": "statement_entry",
	}
	for p := n.Parent; p != nil; p = p.Parent {
		if role, ok := roles[p.Name.Local]; ok {
			return role
		}
	}
	return "message"
}

func normalize(kind, value string) string {
	value = strings.TrimSpace(value)
	switch kind {
	case "bic", "lei", "iban", "other_identifier":
		var b strings.Builder
		for _, r := range strings.ToUpper(value) {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				b.WriteRune(r)
			}
		}
		return b.String()
	case "country":
		return strings.ToUpper(strings.Join(strings.Fields(value), " "))
	default:
		var b strings.Builder
		space := false
		for _, r := range strings.ToUpper(value) {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				b.WriteRune(r)
				space = false
			} else if !space && b.Len() > 0 {
				b.WriteByte(' ')
				space = true
			}
		}
		return strings.TrimSpace(b.String())
	}
}

func Project(env *EvidenceEnvelope) ScreeningProjection {
	requests := make([]ScreeningRequest, 0, env.ScreenableCount)
	for _, e := range env.Elements {
		if !e.MatchEligible {
			continue
		}
		requests = append(requests, ScreeningRequest{
			RequestID:        "isoreq_" + shortHash(env.EnvelopeSHA256, e.ElementID, e.Action, e.NormalizedValue),
			ElementID:        e.ElementID,
			TransactionIndex: e.TransactionIndex,
			FieldPath:        e.FieldPath,
			SemanticRole:     e.SemanticRole,
			QueryKind:        e.Action,
			Value:            e.Value,
			NormalizedValue:  e.NormalizedValue,
		})
	}
	p := ScreeningProjection{
		SchemaVersion:       "openwatchlist.iso20022-screening-projection.v1",
		SourceRef:           env.SourceRef,
		SourceSHA256:        env.SourceSHA256,
		MatrixSHA256:        env.MatrixSHA256,
		ProfileID:           env.ProfileID,
		MessageDefinitionID: env.MessageDefinitionID,
		Requests:            requests,
	}
	p.ProjectionSHA256 = hashStruct(p, func(v *ScreeningProjection) { v.ProjectionSHA256 = "" })
	return p
}

func VerifyEnvelope(matrix *Matrix, env *EvidenceEnvelope) error {
	if env.SchemaVersion != "openwatchlist.iso20022-family-evidence.v1" {
		return errors.New("unsupported evidence schema_version")
	}
	if env.MatrixSHA256 != matrix.SHA256 {
		return errors.New("matrix checksum mismatch")
	}
	expected := hashStruct(*env, func(v *EvidenceEnvelope) { v.EnvelopeSHA256 = "" })
	if env.EnvelopeSHA256 != expected {
		return errors.New("evidence envelope checksum mismatch")
	}
	return nil
}

func walk(n *node, fn func(*node)) {
	fn(n)
	for _, c := range n.Children {
		walk(c, fn)
	}
}

func containsLocal(n *node, local string) bool {
	found := false
	walk(n, func(x *node) {
		if x.Name.Local == local {
			found = true
		}
	})
	return found
}

func nearestTransaction(n *node, tx map[*node]int) int {
	for p := n; p != nil; p = p.Parent {
		if idx, ok := tx[p]; ok {
			return idx
		}
	}
	return 0
}

func nodePath(n *node) string {
	var parts []string
	for p := n; p != nil; p = p.Parent {
		part := p.Name.Local
		if p.Index > 1 || hasSameNamedSibling(p) {
			part = fmt.Sprintf("%s[%d]", part, p.Index)
		}
		parts = append(parts, part)
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return "/" + strings.Join(parts, "/")
}

func hasSameNamedSibling(n *node) bool {
	if n.Parent == nil {
		return false
	}
	count := 0
	for _, s := range n.Parent.Children {
		if s.Name.Local == n.Name.Local {
			count++
		}
	}
	return count > 1
}
