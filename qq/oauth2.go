package qq

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/wsw0108/toauth2"
	"golang.org/x/oauth2"
)

var (
	AuthURL     = "https://graph.qq.com/oauth2.0/authorize"
	TokenURL    = "https://graph.qq.com/oauth2.0/token"
	OpenIDURL   = "https://graph.qq.com/oauth2.0/me"
	UserInfoURL = "https://graph.qq.com/user/get_user_info"
)

type User struct {
	OpenID       string
	Email        string
	Nickname     string
	FigureURL    string
	FigureURL1   string
	FigureURL2   string
	FigureURLqq1 string
	FigureURLqq2 string
	Gender       string

	Raw map[string]interface{}
}

func AuthCodeURL(c *oauth2.Config, state string, opts ...toauth2.AuthCodeOption) string {
	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.AuthURL)
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {c.ClientID},
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
	return buf.String()
}

func tokenRoundTrip(ctx context.Context, req *http.Request) (*oauth2.Token, error) {
	resp, err := toauth2.ContextClient(ctx).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return parseToken(resp.Body)
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
	v.Set("client_id", c.ClientID)
	v.Set("client_secret", c.ClientSecret)
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

func RefreshToken(ctx context.Context, c *oauth2.Config, refreshToken string) (*oauth2.Token, error) {
	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.TokenURL)
	v := url.Values{}
	v.Set("client_id", c.ClientID)
	v.Set("grant_type", "refresh_token")
	v.Set("refresh_token", refreshToken)
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

func getOpenID(ctx context.Context, openIDURL string, accessToken string) (string, error) {
	var buf bytes.Buffer
	buf.WriteString(openIDURL)
	if strings.Contains(openIDURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString("access_token=" + accessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, buf.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := toauth2.ContextClient(ctx).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return parseOpenID(resp.Body)
}

func GetOpenID(ctx context.Context, token *oauth2.Token) (string, error) {
	return getOpenID(ctx, OpenIDURL, token.AccessToken)
}

type userJSON struct {
	Ret          int    `json:"ret"`
	Msg          string `json:"msg"`
	Nickname     string `json:"nickname"`
	FigureURL    string `json:"figureurl"`      // 大小为30×30像素的QQ空间头像URL
	FigureURL1   string `json:"figureurl_1"`    // 大小为50×50像素的QQ空间头像URL
	FigureURL2   string `json:"figureurl_2"`    // 大小为100×100像素的QQ空间头像URL
	FigureURLqq1 string `json:"figureurl_qq_1"` // 大小为40×40像素的QQ头像URL(一定会有)
	FigureURLqq2 string `json:"figureurl_qq_2"` // 大小为100×100像素的QQ头像URL
	Gender       string `json:"gender"`
}

func userRoundTrip(ctx context.Context, c *oauth2.Config, userInfoURL string, accessToken string, openID string, opts ...toauth2.AuthCodeOption) (*http.Response, error) {
	var buf bytes.Buffer
	buf.WriteString(userInfoURL)
	v := url.Values{}
	v.Set("access_token", accessToken)
	v.Set("oauth_consumer_key", c.ClientID)
	v.Set("openid", openID)
	v.Set("format", "json")
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

func getUser(ctx context.Context, c *oauth2.Config, userInfoURL string, accessToken string, openID string, opts ...toauth2.AuthCodeOption) (*User, error) {
	resp, err := userRoundTrip(ctx, c, userInfoURL, accessToken, openID, opts...)
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
	if uj.Ret < 0 {
		return nil, fmt.Errorf("%d: %s", uj.Ret, uj.Msg)
	}
	user := User{
		OpenID:       openID,
		Nickname:     uj.Nickname,
		FigureURL:    uj.FigureURL,
		FigureURL1:   uj.FigureURL1,
		FigureURL2:   uj.FigureURL2,
		FigureURLqq1: uj.FigureURLqq1,
		FigureURLqq2: uj.FigureURLqq2,
		Gender:       uj.Gender,
		Raw:          make(map[string]interface{}),
	}
	json.Unmarshal(body, &user.Raw)
	return &user, nil
}

func GetUser(ctx context.Context, c *oauth2.Config, token *oauth2.Token, opts ...toauth2.AuthCodeOption) (*User, error) {
	openID, err := GetOpenID(ctx, token)
	if err != nil {
		return nil, err
	}
	return getUser(ctx, c, UserInfoURL, token.AccessToken, openID, opts...)
}
