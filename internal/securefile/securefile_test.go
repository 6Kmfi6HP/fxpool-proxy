package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRegularRejectsSymlinkAndBroadMode(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "secret")
	if e := os.WriteFile(p, []byte("x"), 0o644); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadRegular(p, 10, true); e == nil {
		t.Fatal("accepted broad mode")
	}
	if e := os.Chmod(p, 0o600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(d, "link")
	if e := os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadRegular(link, 10, false); e == nil {
		t.Fatal("accepted symlink")
	}
}
