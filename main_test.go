package main_test

import (
	"fmt"
	"testing"

	"pwt-or-jwt/custom"

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

func commonCreation(token custom.Token, b *testing.B) {
	token.AddClaim(custom.Claim{Name: "test", Value: 123})

	for i := 0; i < b.N; i++ {
		_, err := token.Create(secret)
		if err != nil {
			b.Fatalf("error during token creation: %v", err)
		}
	}
}

func commonValidation(token custom.Token, b *testing.B) {
	token.AddClaim(custom.Claim{Name: "test", Value: 123})

	wt, err := token.Create(secret)
	if err != nil {
		b.Fatalf("error during token creation: %v", err)
	}

	for i := 0; i < b.N; i++ {
		err := token.Verify(wt, secret)
		if err != nil {
			b.Fatalf("error during token validation: %v", err)
		}
	}
}

func BenchmarkCustomJWTCreationW(b *testing.B) {
	token := custom.NewJwtToken()
	commonCreation(token, b)
}

func BenchmarkCustomJWTValidation(b *testing.B) {
	token := custom.NewJwtToken()
	commonValidation(token, b)
}

func BenchmarkCustomPWTCreationW(b *testing.B) {
	token := custom.NewPwtToken()
	commonValidation(token, b)
}

func BenchmarkCustomPWTValidation(b *testing.B) {
	token := custom.NewPwtToken()
	commonValidation(token, b)
}
