package jwt

import "time"

type Jwt interface {
	setExpired(expired time.Duration) Jwt
	setSecret(secret string) Jwt
	setHead(alg, typ string) Jwt
	generateSign(head, payload interface{}) (sign, head64, payload64 string)
	Token(obj interface{}) (token string, err error)
	Verify(token string, obj interface{}) error
	Refresh(token *string) error
}

type UserClaims struct {
	Uid         int64  `json:"uid"`
	Username    string `json:"username"`
	Nickname    string `json:"nickname"`
	CountryCode string `json:"country_code"`
	Phone       string `json:"phone"`
	Email       string `json:"email"`
	State       int    `json:"state"`
	Type        int    `json:"type"`
	LastIP      string `json:"last_ip"`
	Expire      int64  `json:"expire"`
	Ext         any    `json:"ext"`
}
