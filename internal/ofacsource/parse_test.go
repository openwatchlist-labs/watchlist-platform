package ofacsource

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "test", "fixtures", "ofac", "sdn", name)
}
func TestParseAndManifest(t *testing.T) {
	a, err := AcquireLocal(fixture(t, "sdn-fixture.xml"), OfficialSDNXMLURL, time.Date(2026, 7, 13, 16, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	if p.Manifest.DeclaredRecordCount != 3 || len(p.Document.Entries) != 3 || len(p.Manifest.ContentSHA256) != 64 {
		t.Fatalf("unexpected manifest %+v", p.Manifest)
	}
}

func TestOfficialLegacyPublishMetadataSpelling(t *testing.T) {
	a, err := AcquireLocal(fixture(t, "sdn-official-publsh-information.xml"), OfficialSDNXMLURL, time.Date(2026, 7, 14, 13, 4, 16, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	if p.Manifest.PublishDate != "07/14/2026" || p.Manifest.DeclaredRecordCount != 1 || len(p.Document.Entries) != 1 {
		t.Fatalf("unexpected official-shape parse result: %+v", p.Manifest)
	}
}

func TestDuplicatePublishMetadataRejected(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><sdnList xmlns="https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML"><publshInformation><Publish_Date>07/14/2026</Publish_Date><Record_Count>1</Record_Count></publshInformation><publishInformation><Publish_Date>07/14/2026</Publish_Date><Record_Count>1</Record_Count></publishInformation><sdnEntry><uid>1</uid><lastName>ONE</lastName><sdnType>Entity</sdnType><programList><program>DEMO</program></programList></sdnEntry></sdnList>`)
	if _, err := parseDocument(data); err == nil || !strings.Contains(err.Error(), "duplicate publication metadata") {
		t.Fatalf("expected duplicate metadata rejection, got %v", err)
	}
}

func TestStrictRejections(t *testing.T) {
	for _, n := range []string{"sdn-bad-record-count.xml", "sdn-unknown-element.xml", "sdn-unsafe-doctype.xml"} {
		t.Run(n, func(t *testing.T) {
			a, err := AcquireLocal(fixture(t, n), OfficialSDNXMLURL, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Parse(a); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}
func TestURLGuard(t *testing.T) {
	for _, u := range []string{
		"http://ofac.treasury.gov/a",
		"https://example.com/a",
		"https://u:p@ofac.treasury.gov/a",
		"https://evil.s3.us-gov-west-1.amazonaws.com/Published/x/SDN.XML",
		"https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com.evil.example/Published/x/SDN.XML",
		"https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com/private/SDN.XML",
		"https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com/Published/x/other.xml",
	} {
		if _, err := validateOfficialURL(u); err == nil {
			t.Fatalf("accepted %s", u)
		}
	}
	if _, err := validateOfficialURL(OfficialSDNXMLURL); err != nil {
		t.Fatal(err)
	}
	redirect := "https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com/Published/release/SDN.XML?X-Amz-Security-Token=secret&X-Amz-Signature=signed"
	if _, err := validateOfficialURL(redirect); err != nil {
		t.Fatal(err)
	}
	if got := redactURL(redirect); got != "https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com/Published/release/SDN.XML" {
		t.Fatalf("unexpected redacted URL %q", got)
	}
}
func TestImmutableArchive(t *testing.T) {
	a, err := AcquireLocal(fixture(t, "sdn-fixture.xml"), OfficialSDNXMLURL, time.Date(2026, 7, 13, 16, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir, err := Archive(root, a, p.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Archive(root, a, p.Manifest); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "source.xml")
	if err = os.WriteFile(path, []byte("tampered"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err = Archive(root, a, p.Manifest); err == nil || !strings.Contains(err.Error(), "immutable archive collision") {
		t.Fatalf("expected collision, got %v", err)
	}
}
