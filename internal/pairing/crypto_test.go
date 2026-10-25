package pairing

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const testProviderKeyID = "sunshine-test-key-1"

func TestPublishedPairingFixtures(t *testing.T) {
	for _, path := range []string{"pairing-v1.json", "pairing-v1-ruby.json"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile("../../docs/fixtures/" + path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				ProviderKeyID          string  `json:"provider_key_id"`
				ProviderPrivateScalar  string  `json:"provider_private_scalar_hex"`
				RecipientPrivateScalar string  `json:"recipient_private_scalar_hex"`
				Now                    int64   `json:"now"`
				RegistrationExpiresAt  int64   `json:"registration_expires_at"`
				Binding                Binding `json:"binding"`
				Plaintext              string  `json:"plaintext"`
				SignedOffer            string  `json:"signed_offer"`
			}
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			providerKey := syntheticP256HexKey(t, fixture.ProviderPrivateScalar)
			deviceKey := syntheticP256HexKey(t, fixture.RecipientPrivateScalar)
			got, err := openOfferForTest(fixture.SignedOffer, fixture.Binding, fixture.RegistrationExpiresAt, fixture.ProviderKeyID, &providerKey.PublicKey, deviceKey, time.Unix(fixture.Now, 0))
			if err != nil {
				t.Fatalf("openOfferForTest(fixture) error = %v", err)
			}
			if string(got) != fixture.Plaintext {
				t.Fatalf("fixture plaintext = %s, want %s", got, fixture.Plaintext)
			}
		})
	}
}

func TestSealAndOpenOffer(t *testing.T) {
	providerKey := syntheticP256Key(2)
	deviceKey := syntheticP256Key(3)
	binding, now, registrationExpiry := testBinding(&deviceKey.PublicKey)
	plaintext := []byte(`{"protocol_version":1,"payload_type":"radio-gaga/v1","secret":"synthetic-only"}`)

	compact, err := sealOfferForTest(binding, plaintext, providerKey, testProviderKeyID, &deviceKey.PublicKey)
	if err != nil {
		t.Fatalf("sealOfferForTest() error = %v", err)
	}
	got, err := openOfferForTest(compact, binding, registrationExpiry, testProviderKeyID, &providerKey.PublicKey, deviceKey, now)
	if err != nil {
		t.Fatalf("openOfferForTest() error = %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("decrypted plaintext = %s, want %s", got, plaintext)
	}
}

func TestOpenOfferRejectsAlteredBindingSignatureAndCiphertext(t *testing.T) {
	providerKey := syntheticP256Key(2)
	deviceKey := syntheticP256Key(3)
	binding, now, registrationExpiry := testBinding(&deviceKey.PublicKey)
	compact, err := sealOfferForTest(binding, []byte(`{"synthetic":true}`), providerKey, testProviderKeyID, &deviceKey.PublicKey)
	if err != nil {
		t.Fatalf("sealOfferForTest() error = %v", err)
	}

	t.Run("binding", func(t *testing.T) {
		mutations := []struct {
			name   string
			change func(*Binding)
		}{
			{name: "session", change: func(value *Binding) { value.SessionID = opaqueID(4) }},
			{name: "generation", change: func(value *Binding) { value.Generation++ }},
			{name: "provider", change: func(value *Binding) { value.ProviderID = "another-provider" }},
			{name: "transaction", change: func(value *Binding) { value.TransactionID = opaqueID(6) }},
			{name: "issued_at", change: func(value *Binding) { value.IssuedAt++ }},
			{name: "expiry", change: func(value *Binding) { value.ExpiresAt-- }},
			{name: "recipient fingerprint", change: func(value *Binding) { value.RecipientKeyFingerprint = opaqueID(7) }},
		}
		for _, mutation := range mutations {
			t.Run(mutation.name, func(t *testing.T) {
				altered := binding
				mutation.change(&altered)
				if _, err := openOfferForTest(compact, altered, registrationExpiry, testProviderKeyID, &providerKey.PublicKey, deviceKey, now); err == nil {
					t.Fatalf("openOfferForTest() accepted altered %s binding", mutation.name)
				}
			})
		}
	})

	t.Run("ciphertext digest", func(t *testing.T) {
		offer := parseTestOffer(t, compact, &providerKey.PublicKey)
		offer.CiphertextDigest = opaqueID(8)
		tampered := signTestOffer(t, offer, providerKey, testProviderKeyID)
		if _, err := openOfferForTest(tampered, binding, registrationExpiry, testProviderKeyID, &providerKey.PublicKey, deviceKey, now); err == nil {
			t.Fatal("openOfferForTest() accepted a changed signed ciphertext digest")
		}
	})

	t.Run("signature", func(t *testing.T) {
		parts := strings.Split(compact, ".")
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		signature[0] ^= 0x01
		parts[2] = base64.RawURLEncoding.EncodeToString(signature)
		if _, err := openOfferForTest(strings.Join(parts, "."), binding, registrationExpiry, testProviderKeyID, &providerKey.PublicKey, deviceKey, now); err == nil {
			t.Fatal("openOfferForTest() accepted an altered signature")
		}
	})

	t.Run("ciphertext authentication", func(t *testing.T) {
		offer := parseTestOffer(t, compact, &providerKey.PublicKey)
		jweParts := strings.Split(offer.Ciphertext, ".")
		ciphertext, err := base64.RawURLEncoding.DecodeString(jweParts[3])
		if err != nil {
			t.Fatal(err)
		}
		ciphertext[0] ^= 0x01
		jweParts[3] = base64.RawURLEncoding.EncodeToString(ciphertext)
		offer.Ciphertext = strings.Join(jweParts, ".")
		offer.CiphertextDigest = digestText(offer.Ciphertext)
		tampered := signTestOffer(t, offer, providerKey, testProviderKeyID)
		if _, err := openOfferForTest(tampered, binding, registrationExpiry, testProviderKeyID, &providerKey.PublicKey, deviceKey, now); err == nil {
			t.Fatal("openOfferForTest() accepted ciphertext with a recomputed digest and valid JWS")
		}
	})
}

func TestOpenOfferRejectsUnapprovedAlgorithmsAndKeyIDs(t *testing.T) {
	providerKey := syntheticP256Key(2)
	deviceKey := syntheticP256Key(3)
	binding, now, registrationExpiry := testBinding(&deviceKey.PublicKey)
	compact, err := sealOfferForTest(binding, []byte(`{"synthetic":true}`), providerKey, testProviderKeyID, &deviceKey.PublicKey)
	if err != nil {
		t.Fatalf("sealOfferForTest() error = %v", err)
	}

	t.Run("provider key id", func(t *testing.T) {
		if _, err := openOfferForTest(compact, binding, registrationExpiry, "unregistered-provider-key", &providerKey.PublicKey, deviceKey, now); err == nil {
			t.Fatal("openOfferForTest() accepted an unregistered provider key ID")
		}
	})

	t.Run("signature algorithm", func(t *testing.T) {
		parts := strings.Split(compact, ".")
		header := decodeTestObject(t, parts[0])
		header["alg"] = json.RawMessage(`"ES384"`)
		parts[0] = encodeTestObject(t, header)
		if _, err := openOfferForTest(strings.Join(parts, "."), binding, registrationExpiry, testProviderKeyID, &providerKey.PublicKey, deviceKey, now); err == nil {
			t.Fatal("openOfferForTest() accepted an unapproved JWS algorithm")
		}
	})

	t.Run("key URL", func(t *testing.T) {
		parts := strings.Split(compact, ".")
		header := decodeTestObject(t, parts[0])
		header["jku"] = json.RawMessage(`"https://attacker.invalid/keys"`)
		parts[0] = encodeTestObject(t, header)
		if _, err := openOfferForTest(strings.Join(parts, "."), binding, registrationExpiry, testProviderKeyID, &providerKey.PublicKey, deviceKey, now); err == nil {
			t.Fatal("openOfferForTest() accepted an external JWS key URL")
		}
	})

	t.Run("JWE algorithm and compression", func(t *testing.T) {
		offer := parseTestOffer(t, compact, &providerKey.PublicKey)
		parts := strings.Split(offer.Ciphertext, ".")
		header := decodeTestObject(t, parts[0])
		header["alg"] = json.RawMessage(`"ECDH-ES"`)
		header["zip"] = json.RawMessage(`"DEF"`)
		parts[0] = encodeTestObject(t, header)
		offer.Ciphertext = strings.Join(parts, ".")
		offer.CiphertextDigest = digestText(offer.Ciphertext)
		tampered := signTestOffer(t, offer, providerKey, testProviderKeyID)
		if _, err := openOfferForTest(tampered, binding, registrationExpiry, testProviderKeyID, &providerKey.PublicKey, deviceKey, now); err == nil {
			t.Fatal("openOfferForTest() accepted an unapproved JWE header")
		}
	})

	t.Run("recipient key id", func(t *testing.T) {
		offer := parseTestOffer(t, compact, &providerKey.PublicKey)
		parts := strings.Split(offer.Ciphertext, ".")
		header := decodeTestObject(t, parts[0])
		header["kid"] = json.RawMessage(`"device-p256-other"`)
		parts[0] = encodeTestObject(t, header)
		offer.Ciphertext = strings.Join(parts, ".")
		offer.CiphertextDigest = digestText(offer.Ciphertext)
		tampered := signTestOffer(t, offer, providerKey, testProviderKeyID)
		if _, err := openOfferForTest(tampered, binding, registrationExpiry, testProviderKeyID, &providerKey.PublicKey, deviceKey, now); err == nil {
			t.Fatal("openOfferForTest() accepted an unapproved recipient key ID")
		}
	})
}

func TestOpenOfferRejectsExpiredAndOversizedOffers(t *testing.T) {
	providerKey := syntheticP256Key(2)
	deviceKey := syntheticP256Key(3)
	binding, now, registrationExpiry := testBinding(&deviceKey.PublicKey)
	compact, err := sealOfferForTest(binding, []byte(`{"synthetic":true}`), providerKey, testProviderKeyID, &deviceKey.PublicKey)
	if err != nil {
		t.Fatalf("sealOfferForTest() error = %v", err)
	}
	if _, err := openOfferForTest(compact, binding, registrationExpiry, testProviderKeyID, &providerKey.PublicKey, deviceKey, time.Unix(binding.ExpiresAt, 0)); err == nil {
		t.Fatal("openOfferForTest() accepted an expired offer")
	}
	if _, err := openOfferForTest(strings.Repeat("a", MaxSignedOfferBytes+1), binding, registrationExpiry, testProviderKeyID, &providerKey.PublicKey, deviceKey, now); err == nil {
		t.Fatal("openOfferForTest() accepted an oversized offer")
	}
}

func TestRecipientFingerprintUsesRFC7638P256Thumbprint(t *testing.T) {
	key := syntheticP256Key(3)
	got := RecipientFingerprint(&key.PublicKey)
	const want = "B3zQUJfL8WPQJT3fRc_9F85aNjqoqRkk-HMzwyAp7WU"
	if got != want {
		t.Fatalf("RecipientFingerprint() = %q, want %q", got, want)
	}
}

func testBinding(deviceKey *ecdsa.PublicKey) (Binding, time.Time, int64) {
	now := time.Unix(2_000_000_000, 0)
	registrationExpiry := now.Add(7 * 24 * time.Hour).Unix()
	binding := Binding{
		ProtocolVersion:         ProtocolVersion,
		SessionID:               opaqueID(1),
		Generation:              4,
		ProviderID:              "sunshine",
		TransactionID:           opaqueID(5),
		IssuedAt:                now.Add(-time.Minute).Unix(),
		ExpiresAt:               now.Add(time.Hour).Unix(),
		RecipientKeyFingerprint: RecipientFingerprint(deviceKey),
	}
	return binding, now, registrationExpiry
}

func syntheticP256Key(scalar int64) *ecdsa.PrivateKey {
	curve := elliptic.P256()
	d := big.NewInt(scalar)
	x, y := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
}

func syntheticP256HexKey(t *testing.T, scalarHex string) *ecdsa.PrivateKey {
	t.Helper()
	scalar, err := hex.DecodeString(scalarHex)
	if err != nil {
		t.Fatal(err)
	}
	return syntheticP256KeyFromScalar(new(big.Int).SetBytes(scalar))
}

func syntheticP256KeyFromScalar(scalar *big.Int) *ecdsa.PrivateKey {
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(scalar.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: scalar}
}

func opaqueID(value byte) string {
	decoded := make([]byte, 32)
	for i := range decoded {
		decoded[i] = value
	}
	return base64.RawURLEncoding.EncodeToString(decoded)
}

func parseTestOffer(t *testing.T, compact string, providerKey *ecdsa.PublicKey) signedOffer {
	t.Helper()
	jws, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := jws.Verify(providerKey)
	if err != nil {
		t.Fatal(err)
	}
	var offer signedOffer
	if err := json.Unmarshal(payload, &offer); err != nil {
		t.Fatal(err)
	}
	return offer
}

func signTestOffer(t *testing.T, offer signedOffer, providerKey *ecdsa.PrivateKey, keyID string) string {
	t.Helper()
	payload, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: providerKey}, (&jose.SignerOptions{}).
		WithHeader(jose.HeaderKey("kid"), keyID).
		WithType(jose.ContentType(OfferJWSContentType)))
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func decodeTestObject(t *testing.T, segment string) map[string]json.RawMessage {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(decoded, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func encodeTestObject(t *testing.T, fields map[string]json.RawMessage) string {
	t.Helper()
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func digestText(compact string) string {
	// Keep the fixture helper aligned with the production compact-JWE digest.
	digest := sha256.Sum256([]byte(compact))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

var (
	opaqueIDPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	keyIDPattern      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	providerIDPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
)

type signedOffer struct {
	ProtocolVersion         int    `json:"protocol_version"`
	SessionID               string `json:"session_id"`
	Generation              uint64 `json:"generation"`
	ProviderID              string `json:"provider_id"`
	TransactionID           string `json:"transaction_id"`
	IssuedAt                int64  `json:"issued_at"`
	ExpiresAt               int64  `json:"expires_at"`
	RecipientKeyFingerprint string `json:"recipient_key_fingerprint"`
	CiphertextDigest        string `json:"ciphertext_digest"`
	Ciphertext              string `json:"ciphertext"`
}

func sealOfferForTest(binding Binding, plaintext []byte, providerSigningKey *ecdsa.PrivateKey, providerKeyID string, recipientKey *ecdsa.PublicKey) (string, error) {
	if err := validateBinding(binding); err != nil {
		return "", err
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintextBytes {
		return "", errors.New("invalid plaintext size")
	}
	if !validP256PrivateKey(providerSigningKey) || !validP256PublicKey(recipientKey) {
		return "", errors.New("P-256 signing and recipient keys are required")
	}
	if !keyIDPattern.MatchString(providerKeyID) || binding.RecipientKeyFingerprint != RecipientFingerprint(recipientKey) {
		return "", errors.New("invalid key binding")
	}

	encryptionOptions := &jose.EncrypterOptions{}
	encryptionOptions.WithContentType(jose.ContentType(OfferJWEContentType))
	for name, value := range map[jose.HeaderKey]interface{}{
		"connect-v":                    binding.ProtocolVersion,
		"connect-sid":                  binding.SessionID,
		"connect-gen":                  binding.Generation,
		"connect-pid":                  binding.ProviderID,
		"connect-tid":                  binding.TransactionID,
		"connect-iat":                  binding.IssuedAt,
		"connect-exp":                  binding.ExpiresAt,
		"connect-recipient-thumbprint": binding.RecipientKeyFingerprint,
	} {
		encryptionOptions.WithHeader(name, value)
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.ECDH_ES_A256KW,
		Key:       recipientKey,
		KeyID:     DeviceKeyID,
	}, encryptionOptions)
	if err != nil {
		return "", fmt.Errorf("create JWE encrypter: %w", err)
	}
	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt offer: %w", err)
	}
	ciphertext, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serialize JWE: %w", err)
	}
	if len(ciphertext) > MaxCiphertextBytes {
		return "", errors.New("encrypted offer exceeds size limit")
	}
	ciphertextDigest := sha256.Sum256([]byte(ciphertext))
	offer := signedOffer{
		ProtocolVersion:         binding.ProtocolVersion,
		SessionID:               binding.SessionID,
		Generation:              binding.Generation,
		ProviderID:              binding.ProviderID,
		TransactionID:           binding.TransactionID,
		IssuedAt:                binding.IssuedAt,
		ExpiresAt:               binding.ExpiresAt,
		RecipientKeyFingerprint: binding.RecipientKeyFingerprint,
		CiphertextDigest:        base64.RawURLEncoding.EncodeToString(ciphertextDigest[:]),
		Ciphertext:              ciphertext,
	}
	payload, err := json.Marshal(offer)
	if err != nil {
		return "", fmt.Errorf("marshal offer: %w", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: providerSigningKey}, (&jose.SignerOptions{}).
		WithHeader(jose.HeaderKey("kid"), providerKeyID).
		WithType(jose.ContentType(OfferJWSContentType)))
	if err != nil {
		return "", fmt.Errorf("create JWS signer: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign offer: %w", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serialize JWS: %w", err)
	}
	if len(compact) > MaxSignedOfferBytes {
		return "", errors.New("signed offer exceeds size limit")
	}
	return compact, nil
}

func openOfferForTest(compact string, expected Binding, registrationExpiresAt int64, providerKeyID string, providerSigningKey *ecdsa.PublicKey, recipientKey *ecdsa.PrivateKey, now time.Time) ([]byte, error) {
	if len(compact) == 0 || len(compact) > MaxSignedOfferBytes {
		return nil, errors.New("invalid signed offer size")
	}
	if err := validateBinding(expected); err != nil {
		return nil, err
	}
	if !keyIDPattern.MatchString(providerKeyID) || providerKeyID == "" || !validP256PublicKey(providerSigningKey) || !validP256PrivateKey(recipientKey) {
		return nil, errors.New("invalid verification keys")
	}
	if expected.RecipientKeyFingerprint != RecipientFingerprint(&recipientKey.PublicKey) || expected.ExpiresAt > registrationExpiresAt {
		return nil, errors.New("recipient or registration expiry mismatch")
	}
	if err := validateOfferTime(expected, registrationExpiresAt, now); err != nil {
		return nil, err
	}

	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errors.New("JWS compact serialization required")
	}
	jwsHeader, err := decodeObjectSegment(parts[0])
	if err != nil || !hasExactKeys(jwsHeader, "alg", "kid", "typ") {
		return nil, errors.New("invalid JWS protected header")
	}
	if stringField(jwsHeader, "alg") != string(jose.ES256) || stringField(jwsHeader, "kid") != providerKeyID || stringField(jwsHeader, "typ") != OfferJWSContentType {
		return nil, errors.New("unexpected JWS protected header")
	}
	jws, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(jws.Signatures) != 1 {
		return nil, errors.New("invalid JWS")
	}
	if jws.Signatures[0].Protected.Algorithm != string(jose.ES256) || jws.Signatures[0].Protected.KeyID != providerKeyID || jws.Signatures[0].Protected.JSONWebKey != nil {
		return nil, errors.New("unexpected JWS key header")
	}
	payload, err := jws.Verify(providerSigningKey)
	if err != nil {
		return nil, errors.New("offer signature verification failed")
	}
	var offer signedOffer
	if err := decodeStrict(payload, &offer); err != nil {
		return nil, errors.New("invalid offer payload")
	}
	if !offerMatchesBinding(offer, expected) {
		return nil, errors.New("offer binding mismatch")
	}
	if len(offer.Ciphertext) == 0 || len(offer.Ciphertext) > MaxCiphertextBytes {
		return nil, errors.New("invalid ciphertext size")
	}
	digest, err := base64.RawURLEncoding.DecodeString(offer.CiphertextDigest)
	if err != nil || len(digest) != sha256.Size || base64.RawURLEncoding.EncodeToString(digest) != offer.CiphertextDigest {
		return nil, errors.New("invalid ciphertext digest")
	}
	actualDigest := sha256.Sum256([]byte(offer.Ciphertext))
	if !bytes.Equal(digest, actualDigest[:]) {
		return nil, errors.New("ciphertext digest mismatch")
	}

	jweParts := strings.Split(offer.Ciphertext, ".")
	if len(jweParts) != 5 {
		return nil, errors.New("JWE compact serialization required")
	}
	jweHeader, err := decodeObjectSegment(jweParts[0])
	if err != nil || !hasExactKeys(jweHeader,
		"alg", "enc", "kid", "cty", "connect-v", "connect-sid", "connect-gen", "connect-pid", "connect-tid", "connect-iat", "connect-exp", "connect-recipient-thumbprint", "epk") {
		return nil, errors.New("invalid JWE protected header")
	}
	if !jweHeaderMatches(jweHeader, expected) || stringField(jweHeader, "kid") != DeviceKeyID || !validEphemeralPublicKey(jweHeader["epk"]) {
		return nil, errors.New("unexpected JWE protected header")
	}
	jwe, err := jose.ParseEncryptedCompact(offer.Ciphertext, []jose.KeyAlgorithm{jose.ECDH_ES_A256KW}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, errors.New("invalid JWE")
	}
	plaintext, err := jwe.Decrypt(recipientKey)
	if err != nil {
		return nil, errors.New("offer decryption failed")
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintextBytes {
		return nil, errors.New("invalid plaintext size")
	}
	return plaintext, nil
}

func validateBinding(binding Binding) error {
	if binding.ProtocolVersion != ProtocolVersion || !validOpaqueID(binding.SessionID) || binding.Generation == 0 ||
		!providerIDPattern.MatchString(binding.ProviderID) || !validOpaqueID(binding.TransactionID) ||
		binding.IssuedAt <= 0 || binding.ExpiresAt <= binding.IssuedAt ||
		binding.ExpiresAt-binding.IssuedAt > int64(MaxOfferLifetime/time.Second) || !validOpaqueID(binding.RecipientKeyFingerprint) {
		return errors.New("invalid offer binding")
	}
	return nil
}

func validateOfferTime(binding Binding, registrationExpiresAt int64, now time.Time) error {
	nowUnix := now.Unix()
	if binding.IssuedAt > nowUnix || binding.ExpiresAt <= nowUnix || binding.ExpiresAt > registrationExpiresAt {
		return errors.New("offer expired or registration expiry exceeded")
	}
	return nil
}

func offerMatchesBinding(offer signedOffer, expected Binding) bool {
	return offer.ProtocolVersion == expected.ProtocolVersion &&
		offer.SessionID == expected.SessionID &&
		offer.Generation == expected.Generation &&
		offer.ProviderID == expected.ProviderID &&
		offer.TransactionID == expected.TransactionID &&
		offer.IssuedAt == expected.IssuedAt &&
		offer.ExpiresAt == expected.ExpiresAt &&
		offer.RecipientKeyFingerprint == expected.RecipientKeyFingerprint
}

func jweHeaderMatches(header map[string]json.RawMessage, expected Binding) bool {
	return stringField(header, "alg") == string(jose.ECDH_ES_A256KW) &&
		stringField(header, "enc") == string(jose.A256GCM) &&
		stringField(header, "cty") == OfferJWEContentType &&
		intField(header, "connect-v") == int64(expected.ProtocolVersion) &&
		stringField(header, "connect-sid") == expected.SessionID &&
		uintField(header, "connect-gen") == expected.Generation &&
		stringField(header, "connect-pid") == expected.ProviderID &&
		stringField(header, "connect-tid") == expected.TransactionID &&
		intField(header, "connect-iat") == expected.IssuedAt &&
		intField(header, "connect-exp") == expected.ExpiresAt &&
		stringField(header, "connect-recipient-thumbprint") == expected.RecipientKeyFingerprint
}

func validEphemeralPublicKey(raw json.RawMessage) bool {
	fields, err := decodeObject(raw)
	if err != nil || !hasExactKeys(fields, "kty", "crv", "x", "y") {
		return false
	}
	return stringField(fields, "kty") == "EC" && stringField(fields, "crv") == "P-256" &&
		validBase64Coordinate(stringField(fields, "x")) && validBase64Coordinate(stringField(fields, "y"))
}

func validBase64Coordinate(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validP256PrivateKey(key *ecdsa.PrivateKey) bool {
	return key != nil && validP256PublicKey(&key.PublicKey) && key.D != nil && key.D.Sign() > 0
}

func validP256PublicKey(key *ecdsa.PublicKey) bool {
	return key != nil && key.Curve == elliptic.P256() && key.X != nil && key.Y != nil && elliptic.P256().IsOnCurve(key.X, key.Y)
}

func validOpaqueID(value string) bool {
	if !opaqueIDPattern.MatchString(value) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func decodeStrict(data []byte, destination any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func decodeObjectSegment(segment string) (map[string]json.RawMessage, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, err
	}
	return decodeObject(decoded)
}

func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return nil, errors.New("JSON object required")
	}
	return fields, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
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
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func hasExactKeys(fields map[string]json.RawMessage, names ...string) bool {
	if len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if _, exists := fields[name]; !exists {
			return false
		}
	}
	return true
}

func stringField(fields map[string]json.RawMessage, name string) string {
	var value string
	if json.Unmarshal(fields[name], &value) != nil {
		return ""
	}
	return value
}

func intField(fields map[string]json.RawMessage, name string) int64 {
	var value int64
	if json.Unmarshal(fields[name], &value) != nil {
		return 0
	}
	return value
}

func uintField(fields map[string]json.RawMessage, name string) uint64 {
	var value uint64
	if json.Unmarshal(fields[name], &value) != nil {
		return 0
	}
	return value
}
