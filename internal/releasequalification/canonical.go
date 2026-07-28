package releasequalification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

func hash(v any) (string, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}
func strict(path string, dst any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if e = dec.Decode(dst); e != nil {
		return e
	}
	if dec.More() {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
func LoadGateSet(path string) (GateSet, error) {
	var g GateSet
	if e := strict(path, &g); e != nil {
		return g, e
	}
	if g.SchemaVersion != "openwatchlist.release-gates.v1" || g.GateSetID == "" {
		return g, fmt.Errorf("invalid gate set")
	}
	decl := g.GateSetSHA256
	g.GateSetSHA256 = ""
	h, e := hash(g)
	if e != nil {
		return g, e
	}
	if decl != "" && decl != h {
		return g, fmt.Errorf("gate set checksum mismatch")
	}
	g.GateSetSHA256 = h
	return g, nil
}
func LoadSuite(path string) (Suite, error) {
	var s Suite
	if e := strict(path, &s); e != nil {
		return s, e
	}
	if s.SchemaVersion != "openwatchlist.evaluation-suite.v1" || s.SuiteID == "" || len(s.Scenarios) == 0 {
		return s, fmt.Errorf("invalid suite")
	}
	decl := s.SuiteSHA256
	s.SuiteSHA256 = ""
	h, e := hash(s)
	if e != nil {
		return s, e
	}
	if decl != "" && decl != h {
		return s, fmt.Errorf("suite checksum mismatch")
	}
	s.SuiteSHA256 = h
	return s, nil
}
func VerifyReport(r Report) error {
	decl := r.ReportSHA256
	r.ReportSHA256 = ""
	h, e := hash(r)
	if e != nil {
		return e
	}
	if decl == "" || decl != h {
		return fmt.Errorf("report checksum mismatch")
	}
	return nil
}
func LoadReport(path string) (Report, error) {
	var r Report
	e := strict(path, &r)
	if e == nil {
		e = VerifyReport(r)
	}
	return r, e
}
