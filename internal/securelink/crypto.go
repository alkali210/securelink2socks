// SPDX-License-Identifier: AGPL-3.0-or-later
package securelink

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
)

const authPublicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2nJO4nAbiAvMzRjKm9nq80A7P
zFjY8fT0kaN+Cz5u0Tk8zhzX2TXMOf+YL16rNOtuKbNwzBQ2Swk53jy8ZKVQ1yYH
O9T4YMkAS3Sz7mVJtZONGORdLISHyS9dqPDVfSuoU4ItiLki+X1aJ/JCWAF7nuPb
UwKFC5Aepns2wGzk/wIDAQAB
-----END PUBLIC KEY-----`

var bodyIV = []byte("securelink666666")

func encryptCBC(key, iv, plain []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil || len(key) != 16 || len(iv) != aes.BlockSize {
		return nil, errors.New("invalid AES key/IV")
	}
	n := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(bytes.Clone(plain), bytes.Repeat([]byte{byte(n)}, n)...)
	cipher.NewCBCEncrypter(b, iv).CryptBlocks(padded, padded)
	return padded, nil
}

func decryptCBC(key, iv, encrypted []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil || len(key) != 16 || len(iv) != aes.BlockSize || len(encrypted) == 0 || len(encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("invalid AES ciphertext")
	}
	plain := bytes.Clone(encrypted)
	cipher.NewCBCDecrypter(b, iv).CryptBlocks(plain, plain)
	n := int(plain[len(plain)-1])
	if n == 0 || n > aes.BlockSize || !bytes.Equal(plain[len(plain)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		return nil, errors.New("invalid AES padding")
	}
	return plain[:len(plain)-n], nil
}

func managementPassword(username string) string {
	b, _ := encryptCBC([]byte("57H4B3987VT3A541"), []byte("1234567890123456"), []byte(username))
	return url.QueryEscape(base64.StdEncoding.EncodeToString(b))
}

func sheetaSign(timestamp, nonce, body string) string {
	digest := sha1.Sum([]byte("secureLink-" + timestamp + "-" + nonce + "-" + body))
	return strings.ToUpper(base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(digest[:]))))
}

func rsaWrap(plain []byte) (string, error) {
	b, _ := pem.Decode([]byte(authPublicKey))
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return "", errors.New("invalid embedded public key")
	}
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, k.(*rsa.PublicKey), plain)
	return base64.StdEncoding.EncodeToString(enc), err
}

// claims inspects metadata only; it does not authenticate a JWT.
func claims(token string) (map[string]json.RawMessage, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 128*1024 {
		return nil, errors.New("invalid JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, errors.New("invalid JWT payload")
	}
	var v map[string]json.RawMessage
	if json.Unmarshal(b, &v) != nil || v == nil {
		return nil, errors.New("invalid JWT claims")
	}
	return v, nil
}

func CallbackCode(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" {
		return "", errors.New("invalid callback URL")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q["code"]) != 1 || strings.TrimSpace(q.Get("code")) == "" || len(q.Get("code")) > 8192 {
		return "", errors.New("callback must contain one nonempty code")
	}
	return q.Get("code"), nil
}
