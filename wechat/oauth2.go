package wechat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://open.weixin.qq.com/connect/qrconnect",
	TokenURL: "https://api.weixin.qq.com/sns/oauth2/access_token",
}

var (
	UserInfoURL = "https://api.weixin.qq.com/sns/userinfo"
)

type User struct {
	OpenID    string `json:"openid"`
	Nickname  string `json:"nickname"`
	Gender    int    `json:"sex"` //值为1时是男性，值为2时是女性，值为0时是未知
	AvatarURL string `json:"headimgurl"`
	Email     string `json:"email"`
}

func AuthCodeURL(c *oauth2.Config, state string) string {
	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.AuthURL)
	v := url.Values{
		"response_type": {"code"},
		"appid":         {c.ClientID},
	}
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}
	if state != "" {
		v.Set("state", state)
	}
	if strings.Contains(c.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	buf.WriteString("#wechat_redirect")
	return buf.String()
}

func Exchange(ctx context.Context, c *oauth2.Config, code string) (*oauth2.Token, error) {
	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.TokenURL)
	v := url.Values{}
	v.Set("grant_type", "authorization_code")
	v.Set("code", code)
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}
	v.Set("appid", c.ClientID)
	v.Set("secret", c.ClientSecret)
	if strings.Contains(c.Endpoint.TokenURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, buf.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var tj tokenJSON
	if err = json.Unmarshal(body, &tj); err != nil {
		return nil, err
	}
	token := &oauth2.Token{
		AccessToken:  tj.AccessToken,
		TokenType:    tj.TokenType,
		RefreshToken: tj.RefreshToken,
		Expiry:       tj.expiry(),
	}
	extra := make(map[string]interface{})
	json.Unmarshal(body, &extra)
	if token.AccessToken == "" {
		return nil, errors.New("oauth2: server response missing access_token")
	}
	token = token.WithExtra(extra)
	return token, err
}

func GetOpenID(_ context.Context, token *oauth2.Token) (string, error) {
	value := token.Extra("openid")
	if openID, ok := value.(string); ok {
		return openID, nil
	}
	return "", errors.New("can not get openID")
}

func GetUser(ctx context.Context, _ *oauth2.Config, token *oauth2.Token) (*User, error) {
	openID, err := GetOpenID(ctx, token)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(UserInfoURL)
	v := url.Values{}
	v.Set("access_token", token.AccessToken)
	v.Set("openid", openID)
	v.Set("lang", "zh_CN")
	if strings.Contains(UserInfoURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, buf.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var user User
	err = json.NewDecoder(resp.Body).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
