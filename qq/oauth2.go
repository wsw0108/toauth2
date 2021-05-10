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
	OpenID    string `json:"openid"`
	Nickname  string `json:"nickname"`
	Gender    string `json:"gender"`
	AvatarURL string `json:"figureurl_qq"`
	Email     string `json:"email"`
}

type meJSON struct {
	OpenID string `json:"openid"`
}

func AuthCodeURL(c *oauth2.Config, state string) string {
	return c.AuthCodeURL(state)
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
	v.Set("client_id", c.ClientID)
	v.Set("client_secret", c.ClientSecret)
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

func GetUser(ctx context.Context, c *oauth2.Config, token *oauth2.Token) (*User, error) {
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
