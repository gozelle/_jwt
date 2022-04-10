package _jwt

import (
	"testing"
	"time"
)

type UserInfo struct {
	Id       int64
	Username string
}

func TestGenerateToken(t *testing.T) {
	salt := "12345678"
	userInfo := UserInfo{
		Id:       1,
		Username: "root",
	}
	token, err := GenerateToken(salt, "srv", time.Now().Add(24*time.Hour).Unix(), userInfo)
	if err != nil {
		t.Error("生成 Token 错误", err)
		return
	}
	t.Log("生成 Token 成功", token)

	userInfo2 := UserInfo{}
	err = ParseToken(salt, token, &userInfo2)
	if err != nil {
		t.Error("解析 Token 错误", err)
		return
	}
	t.Log("解析 Token 成功", userInfo2)
}
