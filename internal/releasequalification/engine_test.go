package releasequalification

import (
	"testing"
)

func TestQualificationAndBlocking(t *testing.T) {
	g, e := LoadGateSet("../../configs/evaluation/phase10-release-gates-r1.json")
	if e != nil {
		t.Fatal(e)
	}
	s, e := LoadSuite("../../test/fixtures/release-qualification/suite.json")
	if e != nil {
		t.Fatal(e)
	}
	r, e := Evaluate(g, s)
	if e != nil {
		t.Fatal(e)
	}
	if r.Status != "qualified" || r.Metrics.FalseNegative != 0 {
		t.Fatalf("%+v", r)
	}
	if e = VerifyReport(r); e != nil {
		t.Fatal(e)
	}
	s.Scenarios[0].Prediction = "clear"
	r, e = Evaluate(g, s)
	if e != nil {
		t.Fatal(e)
	}
	if r.Status != "blocked" {
		t.Fatal("false negative did not block")
	}
}
func TestTamper(t *testing.T) {
	g, _ := LoadGateSet("../../configs/evaluation/phase10-release-gates-r1.json")
	s, _ := LoadSuite("../../test/fixtures/release-qualification/suite.json")
	r, _ := Evaluate(g, s)
	r.Status = "blocked"
	if VerifyReport(r) == nil {
		t.Fatal("tampered report accepted")
	}
}
