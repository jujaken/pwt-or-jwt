package main_test

import (
	"fmt"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/snowmerak/pwt/gen/grpc/model/token"
	"github.com/snowmerak/pwt/lib/pwt"
)

const secret = "test"

func BenchmarkJWTCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"test": 123,
		})
		_, err := jwtToken.SignedString([]byte(secret))
		if err != nil {
			b.Fatalf("Ошибка при подписании JWT: %v", err)
		}
	}
}

func BenchmarkJWTValidation(b *testing.B) {
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"test": 123,
	})
	signedToken, err := jwtToken.SignedString([]byte(secret))
	if err != nil {
		b.Fatalf("Ошибка при подписании JWT: %v", err)
	}

	for i := 0; i < b.N; i++ {
		_, err := jwt.Parse(signedToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("неверный метод подписи: %v", token.Header["alg"])
			}
			return []byte(secret), nil
		})
		if err != nil {
			b.Fatalf("Ошибка при валидации JWT: %v", err)
		}
	}
}

func BenchmarkPWTCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t := pwt.New().SetType(token.Type_REFRESH).SetAlgorithm(token.SignatureAlgorithm_HMAC, token.HashAlgorithm_BLAKE3_256)
		if err := pwt.SetPayload[int64](t, "test", 123); err != nil {
			b.Fatalf("Ошибка при установке полезной нагрузки PWT: %v", err)
		}
		if ok, err := t.Sign([]byte(secret)); ok == "" || err != nil {
			b.Fatalf("Ошибка при подписании PWT: %v", err)
		}
	}
}

func BenchmarkPWTCreationWithExport(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t := pwt.New().SetType(token.Type_REFRESH).SetAlgorithm(token.SignatureAlgorithm_HMAC, token.HashAlgorithm_BLAKE3_256)
		if err := pwt.SetPayload[int64](t, "test", 123); err != nil {
			b.Fatalf("Ошибка при установке полезной нагрузки PWT: %v", err)
		}
		if ok, err := t.Sign([]byte(secret)); ok == "" || err != nil {
			b.Fatalf("Ошибка при подписании PWT: %v", err)
		}
		_, err := t.Export()
		if err != nil {
			b.Fatalf("Ошибка при экспорте PWT: %v", err)
		}
	}
}

func BenchmarkPWTValidation(b *testing.B) {
	t := pwt.New().SetType(token.Type_REFRESH).SetAlgorithm(token.SignatureAlgorithm_HMAC, token.HashAlgorithm_BLAKE3_256)
	if err := pwt.SetPayload[int64](t, "test", 123); err != nil {
		b.Fatalf("Ошибка при установке полезной нагрузки PWT: %v", err)
	}
	if ok, err := t.Sign([]byte(secret)); ok == "" || err != nil {
		b.Fatalf("Ошибка при подписании PWT: %v", err)
	}
	wt, err := t.Export()
	if err != nil {
		b.Fatalf("Ошибка при экспорте PWT: %v", err)
	}

	for i := 0; i < b.N; i++ {
		at, err := pwt.Import(wt)
		if err != nil {
			b.Fatalf("Ошибка при импорте PWT: %v", err)
		}
		if err := at.Verify([]byte(secret)); err != nil {
			b.Fatalf("Ошибка при верификации PWT: %v", err)
		}
	}
}
