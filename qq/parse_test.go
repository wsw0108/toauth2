package qq

import "testing"

func TestParseWeirdOpenID(t *testing.T) {
	body := `callback( {"client_id":"YOUR_APPID","openid":"YOUR_OPENID"} );`
	me, err := parseMeJSONCallbackBytes([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	want := "YOUR_OPENID"
	if me.OpenID != want {
		t.Fatalf("parse, want: %s, got: %s", want, me.OpenID)
	}
}
