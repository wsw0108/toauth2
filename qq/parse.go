package qq

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/oauth2"
)

func parseToken(r io.Reader) (*oauth2.Token, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parseTokenForm(string(body))
}

func parseTokenForm(body string) (*oauth2.Token, error) {
	values, err := url.ParseQuery(body)
	if err != nil {
		return nil, err
	}
	token := &oauth2.Token{
		AccessToken:  values.Get("access_token"),
		TokenType:    values.Get("token_type"),
		RefreshToken: values.Get("refresh_token"),
	}
	e := values.Get("expires_in")
	expires, _ := strconv.Atoi(e)
	if expires != 0 {
		token.Expiry = time.Now().Add(time.Duration(expires) * time.Second)
	}
	if token.AccessToken == "" {
		return nil, errors.New("oauth2: server response missing access_token")
	}
	token = token.WithExtra(values)
	return token, nil
}

// https://wiki.connect.qq.com/unionid%e4%bb%8b%e7%bb%8d
type meJSON struct {
	Error       int    `json:"error"`
	Description string `json:"error_description"`
	ClientID    string `json:"client_id"`
	OpenID      string `json:"openid"`
	UnionID     string `json:"unionid"`
}

func parseMeJSON(r io.Reader) (*meJSON, error) {
	var me meJSON
	err := json.NewDecoder(r).Decode(&me)
	if err != nil {
		return nil, err
	}
	if me.Error != 0 {
		return nil, fmt.Errorf("%d: %s", me.Error, me.Description)
	}
	return &me, nil
}

func parseMeJSONCallback(r io.Reader) (*meJSON, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parseMeJSONCallbackBytes(body)
}

func parseMeJSONCallbackBytes(body []byte) (*meJSON, error) {
	if bytes.Contains(body, []byte("callback")) {
		p1 := bytes.IndexByte(body, '(')
		p2 := bytes.LastIndexByte(body, ')')
		if p1 > 0 && p2 > 0 && p1 < p2 {
			body = body[p1+1 : p2]
		} else {
			return nil, errors.New("invalid response for Get OpenID/UnionID API")
		}
	}
	return parseMeJSON(bytes.NewReader(body))
}
