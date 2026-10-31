package signer

import "testing"

// Info (c): non-ASCII KMS hosts are refused, including ones Unicode case
// folding would turn into an allowed ASCII host.
func TestKMSEndpointNonASCII(t *testing.T) {
	for _, raw := range []string{
		"https://Kms.us-east-1.amazonaws.com/", // KELVIN SIGN: ToLower gives "kms..."
		"https://kms.us-east-1.amazonaws.com。/",
		"https://kms.us-east-1.amazonaws.cöm/",
		"https://kms.us-east-1.аmazonaws.com/", // Cyrillic a
	} {
		if err := checkKMSEndpoint(raw, "us-east-1"); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
	if err := checkKMSEndpoint("https://KMS.US-EAST-1.AMAZONAWS.COM/", "us-east-1"); err != nil {
		t.Errorf("upper-case ASCII host: %v", err)
	}
}

// Info (a): FIPS builds default to the KMS FIPS endpoint unless fips=false
// is explicit; an endpoint override must be a KMS host of the signing region.
func TestKMSEndpointSelection(t *testing.T) {
	for _, tc := range []struct {
		uri, region string
		fipsMode    bool
		want        string
		wantErr     bool
	}{
		{"awskms://alias/k", "us-east-1", false, "https://kms.us-east-1.amazonaws.com/", false},
		{"awskms://alias/k", "us-east-1", true, "https://kms-fips.us-east-1.amazonaws.com/", false},
		{"awskms://alias/k?fips=false", "us-east-1", true, "https://kms.us-east-1.amazonaws.com/", false},
		{"awskms://alias/k?fips=true", "us-east-1", false, "https://kms-fips.us-east-1.amazonaws.com/", false},
		{"awskms://alias/k", "cn-north-1", true, "https://kms.cn-north-1.amazonaws.com.cn/", false},
		{"awskms://alias/k?endpoint=https://kms.us-east-1.amazonaws.com", "us-east-1", true, "https://kms.us-east-1.amazonaws.com", false},
		{"awskms://alias/k?endpoint=https://kms.eu-west-1.amazonaws.com", "us-east-1", false, "", true},
		{"awskms://alias/k?endpoint=https://abc.execute-api.us-east-1.amazonaws.com", "us-east-1", false, "", true},
	} {
		k, err := parseKMSURI(tc.uri)
		if err != nil {
			t.Fatalf("%s: %v", tc.uri, err)
		}
		got, err := kmsEndpoint(k, tc.region, tc.fipsMode)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("%s region %s fips=%v: %q %v, want %q err=%v", tc.uri, tc.region, tc.fipsMode, got, err, tc.want, tc.wantErr)
		}
	}
}
