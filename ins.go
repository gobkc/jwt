package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

type Ins struct {
	secret     string
	Head       Head
	HeadString string
	Expired    time.Duration
	Claims     *UserClaims `json:"claims"`
}

type Head struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func NewJwt(f func() (secret, alg, typ string, expired time.Duration)) Jwt {
	jwt := &Ins{Claims: &UserClaims{}}
	secret, alg, typ, expired := f()
	if alg == `` {
		alg = `HS256`
	}
	if typ == `` {
		typ = `JWT`
	}
	if expired == 0 {
		expired = time.Minute * 30
	}
	return jwt.setSecret(secret).setExpired(expired).setHead("HS256", "JWT")
}

func (j *Ins) setSecret(secret string) Jwt {
	j.secret = secret
	return j
}

func (j *Ins) setExpired(expired time.Duration) Jwt {
	j.Expired = expired
	return j
}

func (j *Ins) setHead(alg, typ string) Jwt {
	j.Head.Alg = alg
	j.Head.Typ = typ
	data, err := json.Marshal(j.Head)
	if err != nil {
		fmt.Println(err.Error())
		return j
	}
	j.HeadString = base64.StdEncoding.EncodeToString(data)
	return j
}

func (j *Ins) Token(obj interface{}) (token string, err error) {
	if reflect.TypeOf(j.Claims) == reflect.TypeOf(obj) {
		reflect.ValueOf(j.Claims).Elem().Set(reflect.ValueOf(obj).Elem())
		j.Claims.Expire = time.Now().Add(j.Expired).Unix()
		reflect.ValueOf(obj).Elem().Set(reflect.ValueOf(j.Claims).Elem())
	}
	sign, head64, payload64 := j.generateSign(j.Head, j.Claims)
	token = fmt.Sprintf("%s.%s.%s", head64, payload64, sign)
	return
}

func (j *Ins) generateSign(head, payload interface{}) (sign, head64, payload64 string) {
	headData, err := json.Marshal(head)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	claimsData, err := json.Marshal(payload)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	payload64 = base64.StdEncoding.EncodeToString(claimsData)
	head64 = base64.StdEncoding.EncodeToString(headData)
	h := hmac.New(sha256.New, []byte(j.secret))
	signFormat := fmt.Sprintf("%s.%s", head64, payload64)
	h.Write([]byte(signFormat))
	sign = hex.EncodeToString(h.Sum(nil))
	return
}

func (j *Ins) Verify(token string, obj interface{}) error {
	tokenList := strings.Split(token, ".")
	if tokenLen := len(tokenList); tokenLen < 3 {
		return errors.New("jwt format error")
	}

	head := Head{}
	HeadDecode, err := base64.StdEncoding.DecodeString(tokenList[0])
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	if err := json.Unmarshal(HeadDecode, &head); err != nil {
		return err
	}
	payload := UserClaims{}
	payloadDecode, err := base64.StdEncoding.DecodeString(tokenList[1])
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	if err := json.Unmarshal(payloadDecode, &payload); err != nil {
		return err
	}
	if sign, _, _ := j.generateSign(j.Head, payload); sign != tokenList[2] {
		return errors.New("signature error")
	}
	payload.Expire = time.Now().Add(j.Expired).Unix()
	if reflect.TypeOf(&payload) == reflect.TypeOf(obj) {
		reflect.ValueOf(obj).Elem().Set(reflect.ValueOf(&payload).Elem())
	}
	return nil
}

func (j *Ins) Refresh(token *string) (err error) {
	claims := UserClaims{}
	if err = j.Verify(*token, &claims); err != nil {
		return err
	}
	claims.Expire = time.Now().Add(j.Expired).Unix()
	if *token, err = j.Token(&claims); err != nil {
		return err
	}
	return nil
}
