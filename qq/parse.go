package qq

import (
	"bytes"
	"encoding/json"
	"errors"
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

type meJSON struct {
	OpenID string `json:"openid"`
}

func parseOpenID(r io.Reader) (string, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return parseOpenIDBytes(body)
}

func parseOpenIDBytes(body []byte) (string, error) {
	if bytes.Contains(body, []byte("callback")) {
		p1 := bytes.IndexByte(body, '(')
		p2 := bytes.LastIndexByte(body, ')')
		if p1 > 0 && p2 > 0 && p1 < p2 {
			body = body[p1+1 : p2]
		} else {
			return "", errors.New("invalid response for Get OpenID API")
		}
	}
	var me meJSON
	err := json.Unmarshal(body, &me)
	return me.OpenID, err
}
