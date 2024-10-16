package custom

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

type JwtToken struct {
	webToken WebToken
}

func NewJwtToken() *JwtToken {
	return &JwtToken{
		webToken: WebToken{
			Header:  Header{Alg: "HS256", Typ: "JWT"},
			Payload: Payload{Claims: []Claim{}},
		},
	}
}

func (t *JwtToken) AddClaim(claim Claim) {
	t.webToken.Payload.Claims = append(t.webToken.Payload.Claims, claim)
}

func (t *JwtToken) GetWebToken() WebToken {
	return t.webToken
}

func (t *JwtToken) Create(secret string) (string, error) {
	headerJson, err := json.Marshal(t.webToken.Header)
	if err != nil {
		return "", err
	}

	payloadJson, err := json.Marshal(t.webToken.Payload)
	if err != nil {
		return "", err
	}

	headerEncoded := base64.StdEncoding.EncodeToString(headerJson)
	payloadEncoded := base64.StdEncoding.EncodeToString(payloadJson)

	unsignedToken := headerEncoded + "." + payloadEncoded

	signature := createSignature(unsignedToken, secret)
	t.webToken.Signature = signature

	token := unsignedToken + "." + signature
	return token, nil
}

func (t *JwtToken) Verify(token string, secret string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token format")
	}

	unsignedToken := parts[0] + "." + parts[1]
	signature := parts[2]

	expectedSignature := createSignature(unsignedToken, secret)
	if signature != expectedSignature {
		return errors.New("invalid signature")
	}

	return nil
}
