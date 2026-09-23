package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateReplaceAndDevicePersistence(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	for _, text := range []string{"first", "second"} {
		if err := Write(p, []byte(text)); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(p)
		if err != nil || string(b) != text {
			t.Fatal("state replacement failed")
		}
	}
	id, err := DeviceID(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := DeviceID(dir)
	if err != nil || id != again || len(id) != 32 {
		t.Fatal("device ID not persistent")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("temporary state leaked")
	}
}

func TestInvalidDeviceID(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "device_id"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := DeviceID(dir); err == nil {
		t.Fatal("invalid device identity accepted")
	}
}
