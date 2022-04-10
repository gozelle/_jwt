package _jwt

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

type Claims struct {
	Values string
	jwt.StandardClaims
}

// GenerateToken 生成 JWT Token
// @param salt 加密的盐
// @param issuer 厂牌
// @param expiresAt 过期时间(Unix)
// @param values 需要存储的额外信息
func GenerateToken(salt, issuer string, expiresAt int64, values interface{}) (token string, err error) {
	str := ""
	if values != nil {
		var b []byte
		b, err = json.Marshal(values)
		if err != nil {
			return
		}
		str = string(b)
	}
	claims := Claims{
		str,
		jwt.StandardClaims{
			ExpiresAt: expiresAt,
			Issuer:    issuer,
		},
	}
	g := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err = g.SignedString([]byte(salt))
	if err != nil {
		return
	}
	return
}

// ParseToken 解析 Token
// @param salt 加密的盐
// @param token 客户端传入的Token
// @param ptr 接收存储 Values 的指针
func ParseToken(salt, token string, ptr interface{}) (err error) {
	p, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(salt), nil
	})
	if p != nil {
		if claims, ok := p.Claims.(*Claims); ok && p.Valid {
			err = json.Unmarshal([]byte(claims.Values), ptr)
			if err != nil {
				err = fmt.Errorf("parse values error: %s", err)
				return
			}
			return
		}
	}
	return
}
