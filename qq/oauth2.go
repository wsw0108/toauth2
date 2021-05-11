package qq

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wsw0108/toauth2"
	"golang.org/x/oauth2"
)

var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://graph.qq.com/oauth2.0/authorize",
	TokenURL: "https://graph.qq.com/oauth2.0/token",
}

var (
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
}

func AuthCodeURL(c *oauth2.Config, state string, opts ...oauth2.AuthCodeOption) string {
	return c.AuthCodeURL(state, opts...)
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	values, err := url.ParseQuery(string(body))
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

func GetOpenID(ctx context.Context, token *oauth2.Token) (string, error) {
	var buf bytes.Buffer
	buf.WriteString(OpenIDURL)
	if strings.Contains(OpenIDURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString("access_token=" + token.AccessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, buf.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if bytes.Contains(body, []byte("callback")) {
		p1 := bytes.IndexByte(body, '(')
		p2 := bytes.LastIndexByte(body, ')')
		body = body[p1:p2]
	}
	var me meJSON
	err = json.Unmarshal(body, &me)
	return me.OpenID, err
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

func GetUser(ctx context.Context, c *oauth2.Config, token *oauth2.Token, opts ...toauth2.AuthCodeOption) (*User, error) {
	openID, err := GetOpenID(ctx, token)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(UserInfoURL)
	v := url.Values{}
	v.Set("access_token", token.AccessToken)
	v.Set("oauth_consumer_key", c.ClientID)
	v.Set("openid", openID)
	v.Set("format", "json")
	for _, opt := range opts {
		opt.SetValue(v)
	}
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
	var uj userJSON
	err = json.NewDecoder(resp.Body).Decode(&uj)
	if err != nil {
		return nil, err
	}
	if uj.Ret < 0 {
		return nil, errors.New(uj.Msg)
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
	}
	return &user, nil
}
