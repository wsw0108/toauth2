package qq

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"fmt"

	"github.com/markbates/goth"
	"github.com/wsw0108/toauth2"
	"golang.org/x/oauth2"
)

// Provider is the implementation of `goth.Provider` for accessing QQ.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	authURL      string
	tokenURL     string
	openIDURL    string
	userInfoURL  string
	authCodeOpts []toauth2.AuthCodeOption
	exchangeOpts []toauth2.AuthCodeOption
	userInfoOpts []toauth2.AuthCodeOption
}

// New creates a new QQ provider and sets up important connection details.
// You should always call `qq.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	return NewCustomisedURL(clientKey, secret, callbackURL, AuthURL, TokenURL, OpenIDURL, UserInfoURL, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, openIDURL, userInfoURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "qq",
		openIDURL:    openIDURL,
		userInfoURL:  userInfoURL,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

func (p *Provider) AuthCodeURLOptions(options ...toauth2.AuthCodeOption) {
	p.authCodeOpts = options
}

func (p *Provider) ExchangeOptions(options ...toauth2.AuthCodeOption) {
	p.exchangeOpts = options
}

func (p *Provider) UserInfoOptions(options ...toauth2.AuthCodeOption) {
	p.userInfoOpts = options
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the qq package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks QQ for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: AuthCodeURL(p.config, state, p.authCodeOpts...),
	}, nil
}

// FetchUser will go to QQ and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
		UserID:       sess.OpenID,
	}

	if sess.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}
	if sess.OpenID == "" {
		return user, fmt.Errorf("%s cannot get user infomation without openid", p.providerName)
	}

	ctx := goth.ContextForClient(p.Client())
	response, err := userRoundTrip(ctx, p.config, p.userInfoURL, sess.AccessToken, sess.OpenID, p.userInfoOpts...)
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return user, err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)

	return user, err
}

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	}
	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	uj := userJSON{}
	err := json.NewDecoder(r).Decode(&uj)
	if err != nil {
		return err
	}
	if uj.Ret != 0 {
		return fmt.Errorf("%d: %s", uj.Ret, uj.Msg)
	}
	user.NickName = uj.Nickname
	user.AvatarURL = uj.FigureURLqq1
	return nil
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return RefreshToken(goth.ContextForClient(p.Client()), p.config, refreshToken)
}
