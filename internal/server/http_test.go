package server

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/librescoot/connect-service/internal/report"
	"github.com/librescoot/connect-service/internal/store"
)

type fakeRecord struct {
	credentialDigest [32]byte
	initialEventID   string
	initialDigest    [32]byte
	receipts         map[string][32]byte
	deleted          bool
}

type fakeRepository struct {
	mu      sync.Mutex
	records map[string]*fakeRecord
	pingErr error
}

func newFakeRepository() *fakeRepository {
	return &fakeRepository{records: make(map[string]*fakeRecord)}
}

func (f *fakeRepository) Register(_ context.Context, id string, credentialDigest [32]byte, payload report.Report) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if record, ok := f.records[id]; ok {
		if record.deleted {
			return store.ErrConflict
		}
		if !hmac.Equal(record.credentialDigest[:], credentialDigest[:]) {
			return store.ErrUnauthorized
		}
		if record.initialEventID == payload.EventID && record.initialDigest == payload.CanonicalDigest() {
			return nil
		}
		return store.ErrConflict
	}
	digest := payload.CanonicalDigest()
	f.records[id] = &fakeRecord{
		credentialDigest: credentialDigest,
		initialEventID:   payload.EventID,
		initialDigest:    digest,
		receipts:         map[string][32]byte{payload.EventID: digest},
	}
	return nil
}

func (f *fakeRepository) UpdateReport(_ context.Context, id string, credentialDigest [32]byte, payload report.Report) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.records[id]
	if !ok || record.deleted || !hmac.Equal(record.credentialDigest[:], credentialDigest[:]) {
		return store.ErrUnauthorized
	}
	digest := payload.CanonicalDigest()
	if existing, ok := record.receipts[payload.EventID]; ok {
		if existing == digest {
			return nil
		}
		return store.ErrConflict
	}
	record.receipts[payload.EventID] = digest
	return nil
}

func (f *fakeRepository) Delete(_ context.Context, id string, credentialDigest [32]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.records[id]
	if !ok || record.deleted || !hmac.Equal(record.credentialDigest[:], credentialDigest[:]) {
		return store.ErrUnauthorized
	}
	record.deleted = true
	record.credentialDigest = [32]byte{}
	record.receipts = nil
	return nil
}

func (f *fakeRepository) Ping(context.Context) error             { return f.pingErr }
func (f *fakeRepository) Sweep(context.Context, time.Time) error { return nil }

type waitingRepository struct {
	*fakeRepository
}

func (r waitingRepository) Register(ctx context.Context, _ string, _ [32]byte, _ report.Report) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestInstallationReportLifecycleAndIdempotency(t *testing.T) {
	repository := newFakeRepository()
	handler := NewHandler(repository, 16*1024, 5*time.Second)
	id := opaqueTestID(1)
	token := opaqueTestToken(3)
	initial := testReport(id, opaqueTestID(2), "1.2.3")
	if got := doJSON(handler, http.MethodPost, "/api/v1/installations", token, initial); got.Code != http.StatusNoContent {
		t.Fatalf("registration status = %d, body %s", got.Code, got.Body)
	}
	if got := doJSON(handler, http.MethodPost, "/api/v1/installations", token, initial); got.Code != http.StatusNoContent {
		t.Fatalf("registration retry status = %d, body %s", got.Code, got.Body)
	}

	update := testReport(id, opaqueTestID(4), "1.2.4")
	path := "/api/v1/installations/" + id + "/report"
	for attempt := 0; attempt < 2; attempt++ {
		if got := doJSON(handler, http.MethodPut, path, token, update); got.Code != http.StatusNoContent {
			t.Fatalf("report status = %d, body %s", got.Code, got.Body)
		}
	}
	changed := testReport(id, update.EventID, "1.2.5")
	if got := doJSON(handler, http.MethodPut, path, token, changed); got.Code != http.StatusConflict {
		t.Fatalf("changed event retry status = %d, want conflict", got.Code)
	}

	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/installations/"+id, nil)
	deleteRequest.Header.Set("Authorization", "Bearer "+token)
	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, body %s", deleteResponse.Code, deleteResponse.Body)
	}
	if got := doJSON(handler, http.MethodPut, path, token, update); got.Code != http.StatusUnauthorized {
		t.Fatalf("report after deletion status = %d, want unauthorized", got.Code)
	}
	if got := doJSON(handler, http.MethodPost, "/api/v1/installations", token, initial); got.Code != http.StatusConflict {
		t.Fatalf("re-registration after deletion status = %d, want conflict", got.Code)
	}
}

func TestStrictRequestValidationAndGenericErrors(t *testing.T) {
	handler := NewHandler(newFakeRepository(), 4096, 5*time.Second)
	id := opaqueTestID(5)

	unsupported := httptest.NewRequest(http.MethodPost, "/api/v1/installations", strings.NewReader("{}"))
	unsupportedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unsupportedResponse, unsupported)
	if unsupportedResponse.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type status = %d", unsupportedResponse.Code)
	}

	oversizedReport, err := json.Marshal(testReport(opaqueTestID(8), opaqueTestID(9), "1.2.3"))
	if err != nil {
		t.Fatal(err)
	}
	tooLargeBody := string(oversizedReport) + strings.Repeat(" ", 5000)
	tooLarge := httptest.NewRequest(http.MethodPost, "/api/v1/installations", strings.NewReader(tooLargeBody))
	tooLarge.Header.Set("Content-Type", "application/json")
	tooLarge.Header.Set("Authorization", "Bearer "+opaqueTestToken(3))
	tooLargeResponse := httptest.NewRecorder()
	handler.ServeHTTP(tooLargeResponse, tooLarge)
	if tooLargeResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d, body %s", tooLargeResponse.Code, tooLargeResponse.Body)
	}

	payload := testReport(id, opaqueTestID(6), "1.2.3")
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	withSerial := strings.TrimSuffix(string(encoded), "}") + `,"serial_number":"secret-hardware-id"}`
	invalid := httptest.NewRequest(http.MethodPost, "/api/v1/installations", strings.NewReader(withSerial))
	invalid.Header.Set("Content-Type", "application/json")
	invalid.Header.Set("Authorization", "Bearer "+opaqueTestToken(3))
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusBadRequest || strings.Contains(invalidResponse.Body.String(), "secret-hardware-id") {
		t.Fatalf("unknown field response = %d %s", invalidResponse.Code, invalidResponse.Body)
	}
	duplicateField := strings.TrimSuffix(string(encoded), "}") + `,"protocol_version":1}`
	duplicateRequest := httptest.NewRequest(http.MethodPost, "/api/v1/installations", strings.NewReader(duplicateField))
	duplicateRequest.Header.Set("Content-Type", "application/json")
	duplicateRequest.Header.Set("Authorization", "Bearer "+opaqueTestToken(3))
	duplicateResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateResponse, duplicateRequest)
	if duplicateResponse.Code != http.StatusBadRequest {
		t.Fatalf("duplicate JSON key status = %d", duplicateResponse.Code)
	}

	wrongMethod := httptest.NewRequest(http.MethodGet, "/api/v1/installations/"+id, nil)
	wrongMethodResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongMethodResponse, wrongMethod)
	if wrongMethodResponse.Code != http.StatusMethodNotAllowed || wrongMethodResponse.Header().Get("Allow") != http.MethodDelete {
		t.Fatalf("method response = %d allow=%q", wrongMethodResponse.Code, wrongMethodResponse.Header().Get("Allow"))
	}

	query := httptest.NewRequest(http.MethodDelete, "/api/v1/installations/"+id+"?debug=secret", nil)
	query.Header.Set("Authorization", "Bearer "+opaqueTestToken(3))
	queryResponse := httptest.NewRecorder()
	handler.ServeHTTP(queryResponse, query)
	if queryResponse.Code != http.StatusBadRequest || strings.Contains(queryResponse.Body.String(), "secret") {
		t.Fatalf("query response = %d %s", queryResponse.Code, queryResponse.Body)
	}
}

func TestRequestTimeoutBoundsRepositoryWork(t *testing.T) {
	repository := waitingRepository{fakeRepository: newFakeRepository()}
	handler := NewHandler(repository, 16*1024, 10*time.Millisecond)
	request := doJSON(handler, http.MethodPost, "/api/v1/installations", opaqueTestToken(3), testReport(opaqueTestID(10), opaqueTestID(11), "1.2.3"))
	if request.Code != http.StatusInternalServerError || strings.Contains(request.Body.String(), "deadline") {
		t.Fatalf("timed out repository response = %d %s", request.Code, request.Body)
	}
}

func TestHealthAndReadinessDoNotExposeDatabaseErrors(t *testing.T) {
	repository := newFakeRepository()
	repository.pingErr = errors.New("database connection password=private")
	handler := NewHandler(repository, 16*1024, 5*time.Second)

	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable || strings.Contains(ready.Body.String(), "private") {
		t.Fatalf("readiness response = %d %s", ready.Code, ready.Body)
	}
	live := httptest.NewRecorder()
	handler.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if live.Code != http.StatusNoContent || live.Body.Len() != 0 {
		t.Fatalf("health response = %d %s", live.Code, live.Body)
	}
}

func TestDeleteRejectsBodyAndMissingCredential(t *testing.T) {
	handler := NewHandler(newFakeRepository(), 16*1024, 5*time.Second)
	id := opaqueTestID(7)
	body := httptest.NewRequest(http.MethodDelete, "/api/v1/installations/"+id, strings.NewReader("{}"))
	bodyResponse := httptest.NewRecorder()
	handler.ServeHTTP(bodyResponse, body)
	if bodyResponse.Code != http.StatusBadRequest {
		t.Fatalf("body on delete status = %d", bodyResponse.Code)
	}

	missingAuth := httptest.NewRequest(http.MethodDelete, "/api/v1/installations/"+id, nil)
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, missingAuth)
	if missingResponse.Code != http.StatusUnauthorized || strings.Contains(missingResponse.Body.String(), "installation") {
		t.Fatalf("missing auth response = %d %s", missingResponse.Code, missingResponse.Body)
	}
}

func doJSON(handler http.Handler, method, path, token string, payload report.Report) *httptest.ResponseRecorder {
	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	request := httptest.NewRequest(method, path, strings.NewReader(string(encoded)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func testReport(id, eventID, version string) report.Report {
	mdbVariant := report.BoardMDB
	mdbVersion := version
	dbcVariant := report.BoardDBC
	payload := report.Report{
		ProtocolVersion: report.ProtocolVersion,
		ConsentVersion:  report.ConsentVersion,
		InstallationID:  id,
		EventID:         eventID,
		MDB: &report.Board{
			BoardVariant:    &mdbVariant,
			FirmwareVersion: &mdbVersion,
			VersionKnown:    true,
			VersionLive:     true,
		},
		DBC:                  &report.Board{BoardVariant: &dbcVariant},
		SoftwareCapabilities: []string{report.CapabilityReporting},
	}
	if err := payload.ValidateAndCanonicalize(); err != nil {
		panic(err)
	}
	return payload
}

func opaqueTestID(fill byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{fill}), 32)))
}

func opaqueTestToken(fill byte) string {
	return opaqueTestID(fill)
}
