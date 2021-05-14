package toauth2

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// TokenRoundTrip, golang.org/x/oauth2/internal/token.go, doTokenRoundTrip
func TokenRoundTrip(ctx context.Context, req *http.Request) (*oauth2.Token, error) {
	// TODO: Content-Type of qq's token response
	return nil, nil
}

func ContextClient(ctx context.Context) *http.Client {
	if ctx != nil {
		if hc, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
			return hc
		}
	}
	return http.DefaultClient
}
