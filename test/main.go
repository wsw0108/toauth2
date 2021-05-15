package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/wsw0108/toauth2/wechat"
	"golang.org/x/oauth2"
)

var (
	port  int
	testW bool
)

func main() {
	flag.IntVar(&port, "p", 80, "Port")
	flag.BoolVar(&testW, "w", true, "Test Wechat")
	flag.Parse()

	if testW {
		testWechat()
	}
}

func makeState() string {
	nonce := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(nonce)
}

func testWechat() {
	clientID := os.Getenv("WECHAT_CLIENT_ID")
	clientSecret := os.Getenv("WECHAT_CLIENT_SECRET")
	redirectURL := os.Getenv("WECHAT_REDIRECT_URL")
	redirect, err := url.Parse(redirectURL)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Path:", redirect.Path)
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  wechat.AuthURL,
			TokenURL: wechat.TokenURL,
		},
		RedirectURL: redirectURL,
		Scopes:      []string{"snsapi_login"},
	}
	state := makeState()
	fmt.Println("AuthCodeURL:", wechat.AuthCodeURL(config, state))

	mux := http.NewServeMux()
	mux.HandleFunc(redirect.Path, func(_ http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			fmt.Println("state mismatch")
			return
		}
		code := q.Get("code")
		fmt.Printf("code: %s\n\n", code)
		token, err := wechat.Exchange(r.Context(), config, code)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("token: %v\n\n", token)
		user, err := wechat.GetUser(r.Context(), config, token)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("user: %v\n\n", user)
		token, err = wechat.RefreshToken(r.Context(), config, token.RefreshToken)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("token: %v\n\n", token)
		user, err = wechat.GetUser(r.Context(), config, token)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("user: %v\n\n", user)
	})
	// hosts: 127.0.0.1 -> domain/ip of the callback url
	addr := fmt.Sprintf(":%d", port)
	http.ListenAndServe(addr, mux)
}
