package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	ProtocolVersion     = 1
	ConsentVersion      = 1
	CapabilityReporting = "connect.reporting.v1"
	CapabilityPairing   = "connect.pairing.v1"
)

type BoardVariant string

const (
	BoardMDB BoardVariant = "unu-mdb"
	BoardDBC BoardVariant = "unu-dbc"
)

type Board struct {
	BoardVariant    *BoardVariant `json:"board_variant"`
	FirmwareVersion *string       `json:"firmware_version"`
	VersionKnown    bool          `json:"version_known"`
	VersionLive     bool          `json:"version_live"`
}

func (b *Board) UnmarshalJSON(data []byte) error {
	if err := requireFields(data, "board_variant", "firmware_version", "version_known", "version_live"); err != nil {
		return err
	}
	type plain Board
	var parsed plain
	if err := decodeStrict(data, &parsed); err != nil {
		return err
	}
	*b = Board(parsed)
	return nil
}

type Report struct {
	ProtocolVersion      int      `json:"protocol_version"`
	ConsentVersion       int      `json:"consent_version"`
	InstallationID       string   `json:"installation_id"`
	EventID              string   `json:"event_id"`
	MDB                  *Board   `json:"mdb,omitempty"`
	DBC                  *Board   `json:"dbc,omitempty"`
	SoftwareCapabilities []string `json:"software_capabilities"`
	InstallerVersion     *string  `json:"installer_version"`
}

func (r *Report) UnmarshalJSON(data []byte) error {
	if err := requireFields(data, "protocol_version", "consent_version", "installation_id", "event_id", "software_capabilities", "installer_version"); err != nil {
		return err
	}
	fields, err := objectFields(data)
	if err != nil {
		return err
	}
	for _, board := range []string{"mdb", "dbc"} {
		if raw, exists := fields[board]; exists && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must be omitted when absent", board)
		}
	}
	type plain Report
	var parsed plain
	if err := decodeStrict(data, &parsed); err != nil {
		return err
	}
	*r = Report(parsed)
	return nil
}

var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)

func (r *Report) ValidateAndCanonicalize() error {
	if r.ProtocolVersion != ProtocolVersion || r.ConsentVersion != ConsentVersion {
		return errors.New("unsupported protocol or consent version")
	}
	if !ValidOpaqueID(r.InstallationID) || !ValidOpaqueID(r.EventID) {
		return errors.New("invalid identifier")
	}
	if r.MDB != nil {
		if err := validateBoard(r.MDB, BoardMDB); err != nil {
			return fmt.Errorf("invalid mdb: %w", err)
		}
	}
	if r.DBC != nil {
		if err := validateBoard(r.DBC, BoardDBC); err != nil {
			return fmt.Errorf("invalid dbc: %w", err)
		}
	}
	if r.SoftwareCapabilities == nil || len(r.SoftwareCapabilities) == 0 || len(r.SoftwareCapabilities) > 2 {
		return errors.New("invalid software capabilities")
	}
	for _, capability := range r.SoftwareCapabilities {
		if capability != CapabilityReporting && capability != CapabilityPairing {
			return errors.New("invalid software capability")
		}
	}
	sort.Strings(r.SoftwareCapabilities)
	if len(r.SoftwareCapabilities) == 2 && r.SoftwareCapabilities[0] == r.SoftwareCapabilities[1] {
		return errors.New("duplicate software capability")
	}
	if r.InstallerVersion != nil && !versionPattern.MatchString(*r.InstallerVersion) {
		return errors.New("invalid installer version")
	}
	return nil
}

func validateBoard(board *Board, expected BoardVariant) error {
	if board.BoardVariant != nil && *board.BoardVariant != expected {
		return errors.New("unrecognized board variant")
	}
	if board.FirmwareVersion == nil {
		if board.VersionKnown || board.VersionLive {
			return errors.New("unknown firmware version has known flags")
		}
		return nil
	}
	if !versionPattern.MatchString(*board.FirmwareVersion) || !board.VersionKnown {
		return errors.New("invalid firmware version")
	}
	return nil
}

func (r Report) CanonicalDigest() [32]byte {
	encoded, _ := json.Marshal(r)
	return sha256.Sum256(encoded)
}

func ValidOpaqueID(value string) bool {
	if len(value) != 43 || strings.Contains(value, "=") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func requireFields(data []byte, required ...string) error {
	fields, err := objectFields(data)
	if err != nil {
		return err
	}
	for _, field := range required {
		if _, ok := fields[field]; !ok {
			return fmt.Errorf("missing %s", field)
		}
	}
	return nil
}

func objectFields(data []byte) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, errors.New("object required")
	}
	return fields, nil
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return nil
}
