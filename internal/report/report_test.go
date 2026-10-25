package report

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testID(fill byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{fill}), 32)))
}

func validReport() Report {
	mdbVariant := BoardMDB
	mdbVersion := "1.2.3"
	dbcVariant := BoardDBC
	return Report{
		ProtocolVersion: ProtocolVersion,
		ConsentVersion:  ConsentVersion,
		InstallationID:  testID(1),
		EventID:         testID(2),
		MDB: &Board{
			BoardVariant:    &mdbVariant,
			FirmwareVersion: &mdbVersion,
			VersionKnown:    true,
			VersionLive:     true,
		},
		DBC: &Board{
			BoardVariant: &dbcVariant,
		},
		SoftwareCapabilities: []string{CapabilityReporting},
	}
}

func TestValidOpaqueID(t *testing.T) {
	if !ValidOpaqueID(testID(4)) {
		t.Fatal("expected a 32-byte base64url ID to be valid")
	}
	for _, value := range []string{"", "not-an-id", testID(4) + "=", strings.Repeat("a", 42)} {
		if ValidOpaqueID(value) {
			t.Fatalf("unexpected valid ID %q", value)
		}
	}
}

func TestReportCanonicalizesCapabilities(t *testing.T) {
	first := validReport()
	first.SoftwareCapabilities = []string{CapabilityPairing, CapabilityReporting}
	second := validReport()
	second.SoftwareCapabilities = []string{CapabilityReporting, CapabilityPairing}
	if err := first.ValidateAndCanonicalize(); err != nil {
		t.Fatal(err)
	}
	if err := second.ValidateAndCanonicalize(); err != nil {
		t.Fatal(err)
	}
	if first.CanonicalDigest() != second.CanonicalDigest() {
		t.Fatal("capability order must not alter the canonical digest")
	}
	if first.SoftwareCapabilities[0] != CapabilityPairing {
		t.Fatalf("capabilities were not sorted: %v", first.SoftwareCapabilities)
	}
}

func TestAbsentBoardIsOmitted(t *testing.T) {
	payload := validReport()
	payload.MDB = nil
	if err := payload.ValidateAndCanonicalize(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"mdb"`) || !strings.Contains(string(encoded), `"dbc"`) {
		t.Fatalf("absent board was not represented by omission: %s", encoded)
	}
}

func TestReportRejectsUnrecognizedVariantAndCapability(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{
			name: "variant",
			mutate: func(payload *Report) {
				value := BoardVariant("free-form")
				payload.MDB.BoardVariant = &value
			},
		},
		{
			name: "capability",
			mutate: func(payload *Report) {
				payload.SoftwareCapabilities = []string{"arbitrary-package-name"}
			},
		},
		{
			name: "unknown version flags",
			mutate: func(payload *Report) {
				payload.MDB.VersionKnown = false
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := validReport()
			test.mutate(&payload)
			if err := payload.ValidateAndCanonicalize(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestReportJSONRequiresNullsAndRejectsExtraFields(t *testing.T) {
	payload, err := json.Marshal(validReport())
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("valid report did not decode: %v", err)
	}
	if err := decoded.ValidateAndCanonicalize(); err != nil {
		t.Fatal(err)
	}

	missingVersion := strings.Replace(string(payload), `"firmware_version":null`, ``, 1)
	if err := json.Unmarshal([]byte(missingVersion), &decoded); err == nil {
		t.Fatal("missing firmware_version must not be treated as unknown")
	}
	withUnknownField := strings.TrimSuffix(string(payload), "}") + `,"hardware_serial":"not-accepted"}`
	if err := json.Unmarshal([]byte(withUnknownField), &decoded); err == nil {
		t.Fatal("unknown fields must be rejected")
	}
}
