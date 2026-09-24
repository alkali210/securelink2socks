// SPDX-License-Identifier: AGPL-3.0-or-later
package control

import (
	"strings"
	"testing"
)

func TestPushContinuation(t *testing.T) {
	input := "PUSH_REPLY,app test,route 192.0.2.0 255.255.255.0,push-continuation 2\x00PUSH_REPLY,cipher AES-128-GCM,ifconfig 192.0.2.2 255.255.255.0,push-continuation 1\x00"
	want := "PUSH_REPLY,app test,route 192.0.2.0 255.255.255.0,cipher AES-128-GCM,ifconfig 192.0.2.2 255.255.255.0"
	got, err := ReadPushReply(strings.NewReader(input))
	if err != nil || got != want {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, s := range []string{
		"PUSH_REPLY,app test,push-continuation 2\x00",
		"PUSH_REPLY,push-continuation 1\x00",
		"PUSH_REPLY,push-continuation 3\x00",
		"PUSH_REPLY,push-continuation 2\x00PUSH_REPLY,cipher AES-128-GCM\x00",
		"PUSH_REPLY,push-continuation 2\x00INFO,test\x00",
	} {
		if _, err := ReadPushReply(strings.NewReader(s)); err == nil {
			t.Fatal("accepted incomplete or malformed bundle")
		}
	}
}
