package securefile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ReadRegular reads a bounded regular file without following a final symlink.
func ReadRegular(path string, limit int64, private bool) ([]byte, error) {
	f, err := openReadNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("file is not a safe regular file")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("file permissions must be 0600")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file is too large")
	}
	return b, nil
}

func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	if err = os.Chmod(path, mode); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err == nil {
		err = d.Sync()
		_ = d.Close()
	}
	if err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	ok = true
	return nil
}

func AtomicJSON(path string, value any, mode os.FileMode) error {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		return err
	}
	return AtomicWrite(path, b.Bytes(), mode)
}
