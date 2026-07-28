package ofaccatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
	"path/filepath"
	"testing"
	"time"
)

func build(t *testing.T, at time.Time) Catalog {
	t.Helper()
	a, err := ofacsource.AcquireLocal(filepath.Join("..", "..", "test", "fixtures", "ofac", "sdn", "sdn-fixture.xml"), ofacsource.OfficialSDNXMLURL, at)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ofacsource.Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Project(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestStableProjection(t *testing.T) {
	a := build(t, time.Date(2026, 7, 13, 16, 0, 0, 0, time.UTC))
	b := build(t, time.Date(2026, 7, 14, 16, 0, 0, 0, time.UTC))
	if a.CatalogChecksum != b.CatalogChecksum || a.CatalogVersion != b.CatalogVersion {
		t.Fatal("acquisition time changed catalog identity")
	}
	want := []string{"1001", "2002", "3003"}
	for i, v := range want {
		if a.Records[i].SourceUID != v {
			t.Fatalf("uid order %v", a.Records)
		}
	}
}
func TestStrictLoadAndTamper(t *testing.T) {
	c := build(t, time.Date(2026, 7, 13, 16, 0, 0, 0, time.UTC))
	b, _ := json.Marshal(c)
	if _, err := Load(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	c.Records[0].PrimaryName = "tampered"
	if ValidateCatalog(c) == nil {
		t.Fatal("tamper accepted")
	}
}
func TestExactOnlyProvider(t *testing.T) {
	p, err := NewProvider(build(t, time.Date(2026, 7, 13, 16, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	r := matcherrequest.CandidateSearchRequest{Query: matcherrequest.QueryValue{NormalizedValue: "ACME IMPORTS LLC"}, MatchRoutes: []canonical.MatchRoute{canonical.RouteNormalizedName}, TargetEntityTypes: []canonical.CandidateType{canonical.CandidateOrganization}}
	m, err := p.Search(context.Background(), r)
	if err != nil || len(m) != 1 {
		t.Fatalf("exact=%d err=%v", len(m), err)
	}
	r.Query.NormalizedValue = "ACME IMPORT"
	m, err = p.Search(context.Background(), r)
	if err != nil || len(m) != 0 {
		t.Fatal("partial name matched")
	}
}
