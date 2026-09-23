// SPDX-License-Identifier: AGPL-3.0-or-later
package storage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func Home() (string, error) {
	if p := os.Getenv("SECURELINK2SOCKS_HOME"); p != "" {
		return filepath.Abs(p)
	}
	p, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(p, ".securelink2socks"), nil
}

// Write uses a same-directory temporary file so readers never see partial JSON.
// On Windows, inherited directory ACLs govern access; mode 0600 is not a DACL.
func Write(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func SaveJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return Write(path, append(b, '\n'))
}

func DeviceID(dir string) (string, error) {
	path := filepath.Join(dir, "device_id")
	b, err := os.ReadFile(path)
	if err == nil {
		id := strings.TrimSpace(string(b))
		decoded, e := hex.DecodeString(id)
		if e != nil || len(decoded) != 16 {
			return "", errors.New("invalid stored device ID")
		}
		return id, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return "", err
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	value := hex.EncodeToString(id[:])
	if err = os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return DeviceID(dir)
	}
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(value)
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	return value, nil
}
