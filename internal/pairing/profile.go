package pairing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	ProtocolVersion     = 1
	DeviceKeyID         = "device-p256-v1"
	OfferJWSContentType = "application/librescoot-pairing-offer+jws"
	OfferJWEContentType = "application/librescoot-pairing-config+json"
	MaxPlaintextBytes   = 32 << 10
	MaxCiphertextBytes  = 48 << 10
	MaxSignedOfferBytes = 64 << 10
	MaxOfferLifetime    = 24 * time.Hour
)

type Binding struct {
	ProtocolVersion         int    `json:"protocol_version"`
	SessionID               string `json:"session_id"`
	Generation              uint64 `json:"generation"`
	ProviderID              string `json:"provider_id"`
	TransactionID           string `json:"transaction_id"`
	IssuedAt                int64  `json:"issued_at"`
	ExpiresAt               int64  `json:"expires_at"`
	RecipientKeyFingerprint string `json:"recipient_key_fingerprint"`
}

func RecipientFingerprint(publicKey *ecdsa.PublicKey) string {
	if publicKey == nil || publicKey.Curve != elliptic.P256() || publicKey.X == nil || publicKey.Y == nil || !elliptic.P256().IsOnCurve(publicKey.X, publicKey.Y) {
		return ""
	}
	thumbprint, err := (&jose.JSONWebKey{Key: publicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint)
}
