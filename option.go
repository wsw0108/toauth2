package toauth2

import "net/url"

// An AuthCodeOption is passed to Config.AuthCodeURL.
type AuthCodeOption interface {
	SetValue(url.Values)
}

type setParam struct{ k, v string }

func (p setParam) SetValue(m url.Values) { m.Set(p.k, p.v) }

// SetAuthURLParam builds an AuthCodeOption which passes key/value parameters
// to a provider's authorization endpoint.
func SetAuthURLParam(key, value string) AuthCodeOption {
	return setParam{key, value}
}
