package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/librescoot/connect-service/internal/report"
	"github.com/librescoot/connect-service/internal/store"
)

type Handler struct {
	repository     store.Repository
	maxBody        int64
	requestTimeout time.Duration
}

func NewHandler(repository store.Repository, maxBody int64, requestTimeout time.Duration) *Handler {
	return &Handler{repository: repository, maxBody: maxBody, requestTimeout: requestTimeout}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.requestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	r.Body = http.MaxBytesReader(w, r.Body, h.maxBody)
	defer r.Body.Close()
	if r.ContentLength > h.maxBody {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}

	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	switch r.URL.Path {
	case "/healthz":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		if !emptyBody(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case "/readyz":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		if !emptyBody(w, r) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if h.repository.Ping(ctx) != nil {
			writeError(w, http.StatusServiceUnavailable, "not_ready")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case "/api/v1/installations":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		h.register(w, r)
		return
	}

	const prefix = "/api/v1/installations/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	resource := strings.TrimPrefix(r.URL.Path, prefix)
	if strings.HasSuffix(resource, "/report") {
		id := strings.TrimSuffix(resource, "/report")
		if !report.ValidOpaqueID(id) || strings.Contains(id, "/") {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		if r.Method != http.MethodPut {
			methodNotAllowed(w, http.MethodPut)
			return
		}
		h.updateReport(w, r, id)
		return
	}
	if !report.ValidOpaqueID(resource) || strings.Contains(resource, "/") {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodDelete {
		methodNotAllowed(w, http.MethodDelete)
		return
	}
	h.delete(w, r, resource)
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	if !jsonContentType(r) {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	credentialDigest, ok := bearerDigest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	payload, ok := decodeReport(w, r)
	if !ok {
		return
	}
	if err := h.repository.Register(r.Context(), payload.InstallationID, credentialDigest, payload); err != nil {
		h.writeRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) updateReport(w http.ResponseWriter, r *http.Request, id string) {
	if !jsonContentType(r) {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	credentialDigest, ok := bearerDigest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	payload, ok := decodeReport(w, r)
	if !ok {
		return
	}
	if payload.InstallationID != id {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := h.repository.UpdateReport(r.Context(), id, credentialDigest, payload); err != nil {
		h.writeRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request, id string) {
	if !emptyBody(w, r) {
		return
	}
	credentialDigest, ok := bearerDigest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := h.repository.Delete(r.Context(), id, credentialDigest); err != nil {
		h.writeRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) writeRepositoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrUnauthorized):
		writeError(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error")
	}
}

func decodeReport(w http.ResponseWriter, r *http.Request) (report.Report, bool) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeDecodeError(w, err)
		return report.Report{}, false
	}
	if hasDuplicateJSONKeys(data) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return report.Report{}, false
	}
	var payload report.Report
	if err := json.Unmarshal(data, &payload); err != nil {
		writeDecodeError(w, err)
		return report.Report{}, false
	}
	if err := payload.ValidateAndCanonicalize(); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return report.Report{}, false
	}
	return payload, true
}

func hasDuplicateJSONKeys(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return true
	}
	var extra any
	return !errors.Is(decoder.Decode(&extra), io.EOF)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	writeError(w, http.StatusBadRequest, "bad_request")
}

func bearerDigest(r *http.Request) ([32]byte, bool) {
	var zero [32]byte
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return zero, false
	}
	token := strings.TrimPrefix(value, "Bearer ")
	if len(token) != 43 {
		return zero, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return zero, false
	}
	return sha256.Sum256(decoded), true
}

func jsonContentType(r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
}

func emptyBody(w http.ResponseWriter, r *http.Request) bool {
	if r.ContentLength > 0 {
		writeError(w, http.StatusBadRequest, "bad_request")
		return false
	}
	n, err := io.CopyN(io.Discard, r.Body, 1)
	if n != 0 || !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return false
	}
	return true
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: code})
}
