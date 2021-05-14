package wechat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/wsw0108/toauth2"
	"golang.org/x/oauth2"
)

var (
	AuthURL     = "https://open.weixin.qq.com/connect/qrconnect"
	TokenURL    = "https://api.weixin.qq.com/sns/oauth2/access_token"
	RefreshURL  = "https://api.weixin.qq.com/sns/oauth2/refresh_token"
	UserInfoURL = "https://api.weixin.qq.com/sns/userinfo"
)

var (
	OptionStyleWhite     toauth2.AuthCodeOption = toauth2.SetAuthURLParam("style", "white")
	OptionStyleBlack     toauth2.AuthCodeOption = toauth2.SetAuthURLParam("style", "black")
	OptionEmptyStyleType toauth2.AuthCodeOption = toauth2.SetAuthURLParam("styletype", "")
	OptionEmptySizeType  toauth2.AuthCodeOption = toauth2.SetAuthURLParam("sizetype", "")
)

type User struct {
	OpenID    string `json:"openid"`
	Nickname  string `json:"nickname"`
	Gender    int    `json:"sex"` //值为1时是男性，值为2时是女性，值为0时是未知
	AvatarURL string `json:"headimgurl"`
	Email     string `json:"email"`
	UnionID   string `json:"unionid"`

	Raw map[string]interface{} `json:"-"`
}

func AuthCodeURL(c *oauth2.Config, state string, opts ...toauth2.AuthCodeOption) string {
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
	for _, opt := range opts {
		opt.SetValue(v)
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

func tokenRoundTrip(ctx context.Context, req *http.Request) (*oauth2.Token, error) {
	resp, err := toauth2.ContextClient(ctx).Do(req)
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
	if tj.ErrCode != 0 {
		return nil, fmt.Errorf("%d: %s", tj.ErrCode, tj.ErrMsg)
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

func Exchange(ctx context.Context, c *oauth2.Config, code string, opts ...toauth2.AuthCodeOption) (*oauth2.Token, error) {
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
	for _, opt := range opts {
		opt.SetValue(v)
	}
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
	return tokenRoundTrip(ctx, req)
}

func doRefreshToken(ctx context.Context, c *oauth2.Config, refreshURL string, refreshToken string) (*oauth2.Token, error) {
	var buf bytes.Buffer
	buf.WriteString(refreshURL)
	v := url.Values{}
	v.Set("appid", c.ClientID)
	v.Set("grant_type", "refresh_token")
	v.Set("refresh_token", refreshToken)
	if strings.Contains(refreshURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, buf.String(), nil)
	if err != nil {
		return nil, err
	}
	return tokenRoundTrip(ctx, req)
}

// TODO: TokenSource?
func RefreshToken(ctx context.Context, c *oauth2.Config, refreshToken string) (*oauth2.Token, error) {
	return doRefreshToken(ctx, c, RefreshURL, refreshToken)
}

func GetOpenID(_ context.Context, token *oauth2.Token) (string, error) {
	value := token.Extra("openid")
	if openID, ok := value.(string); ok {
		return openID, nil
	}
	return "", errors.New("can not get openID")
}

type userJSON struct {
	ErrCode   int    `json:"errcode"`
	ErrMsg    string `json:"errmsg"`
	OpenID    string `json:"openid"`
	Nickname  string `json:"nickname"`
	Gender    int    `json:"sex"`
	Province  string `json:"province"`
	City      string `json:"city"`
	Country   string `json:"country"`
	AvatarURL string `json:"headimgurl"`
	Email     string `json:"email"`
	UnionID   string `json:"unionid"`
}

func userRoundTrip(ctx context.Context, userInfoURL string, accessToken string, openID string, opts ...toauth2.AuthCodeOption) (*http.Response, error) {
	var buf bytes.Buffer
	buf.WriteString(userInfoURL)
	v := url.Values{}
	v.Set("access_token", accessToken)
	v.Set("openid", openID)
	v.Set("lang", "zh_CN")
	for _, opt := range opts {
		opt.SetValue(v)
	}
	if strings.Contains(userInfoURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, buf.String(), nil)
	if err != nil {
		return nil, err
	}
	return toauth2.ContextClient(ctx).Do(req)
}

func getUser(ctx context.Context, userInfoURL string, accessToken string, openID string, opts ...toauth2.AuthCodeOption) (*User, error) {
	resp, err := userRoundTrip(ctx, userInfoURL, accessToken, openID, opts...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var uj userJSON
	err = json.Unmarshal(body, &uj)
	if err != nil {
		return nil, err
	}
	if uj.ErrCode != 0 {
		return nil, fmt.Errorf("%d: %s", uj.ErrCode, uj.ErrMsg)
	}
	user := User{
		OpenID:    uj.OpenID,
		Nickname:  uj.Nickname,
		Gender:    uj.Gender,
		AvatarURL: uj.AvatarURL,
		Email:     uj.Email,
		UnionID:   uj.UnionID,
		Raw:       make(map[string]interface{}),
	}
	json.Unmarshal(body, &user.Raw)
	return &user, nil
}

func GetUser(ctx context.Context, _ *oauth2.Config, token *oauth2.Token, opts ...toauth2.AuthCodeOption) (*User, error) {
	openID, err := GetOpenID(ctx, token)
	if err != nil {
		return nil, err
	}
	return getUser(ctx, UserInfoURL, token.AccessToken, openID, opts...)
}
