package runtimemmapclient

import "testing"

func TestProtocolRoundTrip(t *testing.T) {
	info, err := parseHello("H\t1\t636174616c6f675f636f6d706f6e656e745f31\t636174616c6f67\t7631\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t6f6666696369616c5f6c697374\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t3")
	if err != nil {
		t.Fatal(err)
	}
	if info.ComponentID != "catalog_component_1" || info.CatalogMode != "official_list" || info.RecordCount != 3 {
		t.Fatalf("unexpected hello: %+v", info)
	}
	line, err := encodeQuery(Query{RequestID: "request-1", Kind: QueryName, Value: "ACME IMPORTS", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if line != "Q\trequest-1\tname\t20\t0\t41434d4520494d504f525453" {
		t.Fatalf("unexpected query: %s", line)
	}
	candidate, err := parseCandidate("C\trequest-1\t7265636f72642d31\t6f7267616e697a6174696f6e\t41636d6520496d706f727473\t616c696173\t41434d4520494d504f525453\t61636d6520696d706f727473", "request-1")
	if err != nil {
		t.Fatal(err)
	}
	if candidate.RecordID != "record-1" || candidate.MatchKind != "alias" {
		t.Fatalf("unexpected candidate: %+v", candidate)
	}
}
