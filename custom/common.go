package custom

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

type Header struct {
	Alg string
	Typ string
}

type Claim struct {
	Name  string
	Value int
}

type Payload struct {
	Claims []Claim
}

type WebToken struct {
	Header    Header
	Payload   Payload
	Signature string
}

type Token interface {
	Create(secret string) (string, error)
	AddClaim(claim Claim)
	GetWebToken() WebToken
	Verify(token string, secret string) error
}

func createSignature(data string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
