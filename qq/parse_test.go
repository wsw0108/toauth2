package qq

import "testing"

func TestParseWeirdOpenID(t *testing.T) {
	body := `callback( {"client_id":"YOUR_APPID","openid":"YOUR_OPENID"} );`
	id, err := parseOpenIDBytes([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	want := "YOUR_OPENID"
	if id != want {
		t.Fatalf("parse, want: %s, got: %s", want, id)
	}
}
