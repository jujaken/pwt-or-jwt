package custom

import (
	"encoding/base64"
	"errors"
	"fmt"
	"pwt-or-jwt/custom/auto"
	"strings"

	"google.golang.org/protobuf/proto"
)

type PwtToken struct {
	webToken WebToken
}

func NewPwtToken() *PwtToken {
	return &PwtToken{
		webToken: WebToken{
			Header:  Header{Alg: "HS256", Typ: "PWT"},
			Payload: Payload{Claims: []Claim{}},
		},
	}
}

func (t *PwtToken) AddClaim(claim Claim) {
	t.webToken.Payload.Claims = append(t.webToken.Payload.Claims, claim)
}

func (t *PwtToken) GetWebToken() WebToken {
	return t.webToken
}

func (t *PwtToken) Create(secret string) (string, error) {
	token := t.webToken

	header := &auto.Header{
		Alg: token.Header.Alg,
		Typ: token.Header.Typ,
	}

	claims := make([]*auto.Claim, len(token.Payload.Claims))
	for i, claim := range token.Payload.Claims {
		claims[i] = &auto.Claim{
			Name:  claim.Name,
			Value: int32(claim.Value),
		}
	}

	payload := &auto.Payload{
		Claims: claims,
	}

	headerBytes, err := proto.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Создание подписи
	signatureData := fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString(headerBytes), base64.RawURLEncoding.EncodeToString(payloadBytes))
	token.Signature = createSignature(signatureData, secret)
	pwt := fmt.Sprintf("%s.%s.%s", base64.RawURLEncoding.EncodeToString(headerBytes), base64.RawURLEncoding.EncodeToString(payloadBytes), token.Signature)

	return pwt, nil
}

func (t *PwtToken) Verify(token string, secret string) error {
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
