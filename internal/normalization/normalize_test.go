package normalization

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		profile string
		input   string
		want    string
	}{
		{ProfilePartyName, "  Acme\tImports  LLC ", "ACME IMPORTS LLC"},
		{ProfileIBAN, " gb82 west 1234 ", "GB82WEST1234"},
		{ProfileCountryCode, " us ", "US"},
		{ProfileAmount, " 1250.00 ", "1250.00"},
	}
	for _, test := range tests {
		got, err := Normalize(test.profile, test.input)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", test.profile, err)
		}
		if got != test.want {
			t.Fatalf("Normalize(%q, %q) = %q, want %q", test.profile, test.input, got, test.want)
		}
	}
}
