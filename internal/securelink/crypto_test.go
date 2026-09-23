package securelink

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func TestCryptoGolden(t *testing.T) {
	b, err := os.ReadFile("../../testdata/securelink/crypto.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	enc, err := encryptCBC([]byte(v["key"]), bodyIV, []byte(v["plaintext"]))
	if err != nil {
		t.Fatal(err)
	}
	if base64.StdEncoding.EncodeToString(enc) != v["ciphertext_base64"] {
		t.Fatal("AES golden mismatch")
	}
	plain, err := decryptCBC([]byte(v["key"]), bodyIV, enc)
	if err != nil || string(plain) != v["plaintext"] {
		t.Fatal("decrypt mismatch")
	}
	if managementPassword(v["management_username"]) != v["management_password"] {
		t.Fatal("management password mismatch")
	}
	if sheetaSign(v["timestamp"], v["nonce"], v["signed_body"]) != v["signature"] {
		t.Fatal("signature mismatch")
	}
	if wrapped, err := rsaWrap([]byte(v["key"])); err != nil {
		t.Fatal(err)
	} else if b, e := base64.StdEncoding.DecodeString(wrapped); e != nil || len(b) != 128 {
		t.Fatal("invalid RSA-wrapped key length")
	}
}

func TestCBCRejectsMalformed(t *testing.T) {
	key := []byte("0123456789abcdef")
	for _, b := range [][]byte{nil, {1}, make([]byte, 16)} {
		if _, err := decryptCBC(key, bodyIV, b); err == nil {
			t.Fatal("accepted invalid ciphertext")
		}
	}
	for n := 0; n < 64; n++ {
		src := bytes.Repeat([]byte{byte(n)}, n)
		enc, err := encryptCBC(key, bodyIV, src)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := decryptCBC(key, bodyIV, enc)
		if err != nil || !bytes.Equal(src, dec) {
			t.Fatalf("round trip length %d", n)
		}
	}
}

func testJWT(payload string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".synthetic-signature"
}

func TestClaims(t *testing.T) {
	if c, err := claims(testJWT(`{"username":"test","exp":2000000000}`)); err != nil || string(c["username"]) != `"test"` {
		t.Fatal("claims decode failed")
	}
	for _, token := range []string{"", "a.b", "a.!!.c", testJWT(`null`), testJWT(`[]`)} {
		if _, err := claims(token); err == nil {
			t.Fatal("invalid claims accepted")
		}
	}
}

func TestCallbackCode(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{{"securelink://callback?other=1&code=a%2Bb%2Fc", "a+b/c"}, {"https://example.invalid/?code=test#fragment", "test"}} {
		got, err := CallbackCode(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("callback: %q %v", got, err)
		}
	}
	for _, raw := range []string{"", "?code=abc", "securelink://callback?code=", "securelink://callback?code=a&code=b", "securelink://callback?code=%zz"} {
		if _, err := CallbackCode(raw); err == nil {
			t.Fatal("invalid callback accepted")
		}
	}
}

func FuzzDecryptCBC(f *testing.F) {
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4096 {
			t.Skip()
		}
		_, _ = decryptCBC([]byte("0123456789abcdef"), bodyIV, b)
	})
}
