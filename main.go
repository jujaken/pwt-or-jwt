package main

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/snowmerak/pwt/gen/grpc/model/token"
	"github.com/snowmerak/pwt/lib/pwt"
)

const secret = "test"

func getJwtToken() string {
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"test": 123,
	})
	signedToken, err := jwtToken.SignedString([]byte(secret))
	if err != nil {
		panic(fmt.Sprintf("Ошибка при подписании JWT: %v", err))
	}
	return signedToken
}

func getPwtToken() string {
	t := pwt.New().SetType(token.Type_REFRESH).SetAlgorithm(token.SignatureAlgorithm_HMAC, token.HashAlgorithm_BLAKE3_256)
	if err := pwt.SetPayload[int64](t, "test", 123); err != nil {
		panic(fmt.Sprintf("Ошибка при установке полезной нагрузки PWT: %v", err))
	}
	if ok, err := t.Sign([]byte(secret)); ok == "" || err != nil {
		panic(fmt.Sprintf("Ошибка при подписании PWT: %v", err))
	}
	wt, err := t.Export()
	if err != nil {
		panic(fmt.Sprintf("Ошибка при экспорте PWT: %v", err))
	}
	return wt
}

func main() {
	jwtToken := getJwtToken()
	fmt.Printf("JWT Token: %s\n", jwtToken)
	fmt.Printf("JWT Token len: %d\n", len(jwtToken))

	pwtToken := getPwtToken()
	fmt.Printf("PWT Token: %s\n", pwtToken)
	fmt.Printf("PWT Token len: %d\n", len(pwtToken))
}
