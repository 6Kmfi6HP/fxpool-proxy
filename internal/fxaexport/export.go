// Package fxaexport extracts minimal Firefox IP Protection renewal credentials
// from a local desktop Firefox profile's signedInUser.json.
//
// The long-lived secret is the FxA sessionToken stored plaintext in the profile
// (see notes/verification-log.md and FxAccountsStorage.sys.mjs). Cookies and
// logins.json are not used for IPP renewal.
package fxaexport

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
)

const (
	BundleSchema = "firefox-ip-protection-renewal-credentials-v1"
	maxSignedIn  = 1 << 20 // 1 MiB, same bound as the offline HTML exporter
)

var (
	emailRe = regexp.MustCompile(`^[^\s@]+@[^\s@]+$`)
	uidRe   = regexp.MustCompile(`(?i)^[0-9a-f]{32}$`)
	tokRe   = regexp.MustCompile(`(?i)^[0-9a-f]{64}$`)
)

// Bundle is the transfer format accepted by fxpool-proxy import-credentials.
type Bundle struct {
	Schema       string `json:"schema"`
	Email        string `json:"email"`
	UID          string `json:"uid"`
	SessionToken string `json:"session_token"`
}

// Profile describes a Firefox profile root that may contain FxA state.
type Profile struct {
	Name      string
	Path      string
	IsDefault bool
	Relative  bool
}

// Candidate describes an extractable profile and why it succeeded or failed.
type Candidate struct {
	Profile Profile
	Bundle  *Bundle
	Source  string // absolute path to signedInUser.json when present
	Error   error
}

// FirefoxRoots returns likely Firefox configuration roots for the current OS.
func FirefoxRoots() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	var roots []string
	switch runtime.GOOS {
	case "darwin":
		roots = append(roots, filepath.Join(home, "Library", "Application Support", "Firefox"))
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			roots = append(roots, filepath.Join(appdata, "Mozilla", "Firefox"))
		}
	default:
		roots = append(roots,
			filepath.Join(home, ".mozilla", "firefox"),
			filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
			filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
		)
	}
	out := make([]string, 0, len(roots))
	seen := map[string]bool{}
	for _, r := range roots {
		if r == "" || seen[r] {
			continue
		}
		if st, err := os.Stat(r); err == nil && st.IsDir() {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// ListProfiles parses profiles.ini under root and returns profile entries.
func ListProfiles(root string) ([]Profile, error) {
	iniPath := filepath.Join(root, "profiles.ini")
	b, err := readBounded(iniPath, 256<<10)
	if err != nil {
		return nil, fmt.Errorf("read profiles.ini: %w", err)
	}
	sections := parseINI(string(b))
	var profiles []Profile
	installDefault := ""
	for name, kv := range sections {
		if strings.HasPrefix(name, "Install") {
			if d := kv["Default"]; d != "" {
				installDefault = d
			}
		}
	}
	for name, kv := range sections {
		if !strings.HasPrefix(name, "Profile") {
			continue
		}
		path := kv["Path"]
		if path == "" {
			continue
		}
		rel := kv["IsRelative"] == "1" || kv["IsRelative"] == ""
		abs := path
		if rel {
			abs = filepath.Join(root, filepath.FromSlash(path))
		}
		p := Profile{
			Name:     kv["Name"],
			Path:     abs,
			Relative: rel,
		}
		if p.Name == "" {
			p.Name = filepath.Base(abs)
		}
		pathSlash := filepath.ToSlash(path)
		installSlash := filepath.ToSlash(installDefault)
		switch {
		case installDefault != "" && (path == installDefault || pathSlash == installSlash):
			p.IsDefault = true
		case installDefault == "" && kv["Default"] == "1":
			p.IsDefault = true
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

// DiscoverCandidates walks known Firefox roots and attempts extraction.
func DiscoverCandidates(extraRoots ...string) ([]Candidate, error) {
	roots := FirefoxRoots()
	for _, r := range extraRoots {
		if r == "" {
			continue
		}
		abs, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		dup := false
		for _, existing := range roots {
			if samePath(existing, abs) {
				dup = true
				break
			}
		}
		if !dup {
			roots = append(roots, abs)
		}
	}
	if len(roots) == 0 {
		return nil, errors.New("no Firefox configuration directory found")
	}
	return discoverInRoots(roots)
}

// DiscoverInRoot scans a single Firefox configuration root (the directory that
// contains profiles.ini), or a single profile directory if signedInUser.json is present.
func DiscoverInRoot(root string) ([]Candidate, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(filepath.Join(abs, "signedInUser.json")); err == nil && st.Mode().IsRegular() {
		return []Candidate{InspectProfile(Profile{Name: filepath.Base(abs), Path: abs, IsDefault: true})}, nil
	}
	return discoverInRoots([]string{abs})
}

func discoverInRoots(roots []string) ([]Candidate, error) {
	seenPath := map[string]bool{}
	var out []Candidate
	for _, root := range roots {
		profiles, err := ListProfiles(root)
		if err != nil {
			profiles = scanProfilesDir(root)
		} else {
			for _, p := range scanProfilesDir(root) {
				dup := false
				for _, e := range profiles {
					if samePath(e.Path, p.Path) {
						dup = true
						break
					}
				}
				if !dup {
					profiles = append(profiles, p)
				}
			}
		}
		for _, p := range profiles {
			if seenPath[p.Path] {
				continue
			}
			seenPath[p.Path] = true
			out = append(out, InspectProfile(p))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no Firefox profiles found")
	}
	return out, nil
}

// InspectProfile tries to extract a renewal bundle from one profile.
func InspectProfile(p Profile) Candidate {
	src := filepath.Join(p.Path, "signedInUser.json")
	c := Candidate{Profile: p, Source: src}
	b, err := ExtractFile(src)
	if err != nil {
		c.Error = err
		return c
	}
	c.Bundle = &b
	return c
}

// ExtractFile reads and validates signedInUser.json into a transfer Bundle.
func ExtractFile(path string) (Bundle, error) {
	raw, err := readBounded(path, maxSignedIn)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
			return Bundle{}, errors.New("Firefox Account not signed in (signedInUser.json missing)")
		}
		return Bundle{}, err
	}
	return ParseSignedInUser(raw)
}

// ParseSignedInUser validates the Firefox FxA storage document and returns the
// minimal renewal pack consumed by import-credentials.
func ParseSignedInUser(raw []byte) (Bundle, error) {
	var doc struct {
		Version     int `json:"version"`
		AccountData *struct {
			Email        string `json:"email"`
			UID          string `json:"uid"`
			SessionToken string `json:"sessionToken"`
			Verified     bool   `json:"verified"`
			Device       *struct {
				ID string `json:"id"`
			} `json:"device"`
		} `json:"accountData"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Bundle{}, errors.New("signedInUser.json is not valid JSON")
	}
	if doc.Version != 1 {
		return Bundle{}, errors.New("unrecognized Firefox Account storage version")
	}
	account := doc.AccountData
	if account == nil {
		return Bundle{}, errors.New("signedInUser.json has no accountData")
	}
	if !account.Verified {
		return Bundle{}, errors.New("Firefox Account is not verified")
	}
	if !emailRe.MatchString(account.Email) || len(account.Email) > 320 {
		return Bundle{}, errors.New("signedInUser.json has no valid email")
	}
	if !uidRe.MatchString(account.UID) {
		return Bundle{}, errors.New("signedInUser.json has no valid uid")
	}
	if !tokRe.MatchString(account.SessionToken) {
		return Bundle{}, errors.New("no renewable session token; confirm Firefox is still signed in")
	}
	if account.Device == nil || account.Device.ID == "" ||
		len(account.Device.ID) < 16 || len(account.Device.ID) > 256 {
		return Bundle{}, errors.New("device registration incomplete; keep Firefox online and reopen it")
	}
	if _, err := hex.DecodeString(account.UID); err != nil {
		return Bundle{}, errors.New("invalid uid")
	}
	if _, err := hex.DecodeString(account.SessionToken); err != nil {
		return Bundle{}, errors.New("invalid session token")
	}
	return Bundle{
		Schema:       BundleSchema,
		Email:        account.Email,
		UID:          strings.ToLower(account.UID),
		SessionToken: strings.ToLower(account.SessionToken),
	}, nil
}

// Select chooses one successful candidate.
// Prefer an explicit profile name/path match; otherwise the default profile;
// otherwise the sole success. Multiple successes without a default are an error.
func Select(cands []Candidate, want string) (Candidate, error) {
	want = strings.TrimSpace(want)
	var ok []Candidate
	for _, c := range cands {
		if c.Bundle == nil {
			continue
		}
		if want != "" {
			if matchProfile(c.Profile, want) {
				return c, nil
			}
			continue
		}
		ok = append(ok, c)
	}
	if want != "" {
		return Candidate{}, fmt.Errorf("no extractable credentials for profile %q", want)
	}
	if len(ok) == 0 {
		var first error
		for _, c := range cands {
			if c.Error != nil {
				first = c.Error
				break
			}
		}
		if first == nil {
			first = errors.New("no signed-in Firefox profile found")
		}
		return Candidate{}, fmt.Errorf("no extractable renewal credentials: %w", first)
	}
	if len(ok) == 1 {
		return ok[0], nil
	}
	var defaults []Candidate
	for _, c := range ok {
		if c.Profile.IsDefault {
			defaults = append(defaults, c)
		}
	}
	if len(defaults) == 1 {
		return defaults[0], nil
	}
	names := make([]string, 0, len(ok))
	for _, c := range ok {
		names = append(names, c.Profile.Name)
	}
	return Candidate{}, fmt.Errorf("multiple signed-in profiles (%s); pass --profile", strings.Join(names, ", "))
}

// EncodeBundle returns pretty-printed JSON with trailing newline.
func EncodeBundle(b Bundle) ([]byte, error) {
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func matchProfile(p Profile, want string) bool {
	if strings.EqualFold(p.Name, want) {
		return true
	}
	if samePath(p.Path, want) {
		return true
	}
	base := filepath.Base(p.Path)
	return strings.EqualFold(base, want) || strings.HasPrefix(base, want+".")
}

func samePath(a, b string) bool {
	aa, ea := filepath.Abs(a)
	bb, eb := filepath.Abs(b)
	if ea != nil || eb != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return aa == bb
}

func scanProfilesDir(root string) []Profile {
	dir := filepath.Join(root, "Profiles")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Profile
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		out = append(out, Profile{
			Name: e.Name(),
			Path: filepath.Join(dir, e.Name()),
		})
	}
	return out
}

func readBounded(path string, limit int64) ([]byte, error) {
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
		return nil, errors.New("not a regular file")
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

// parseINI is a minimal profiles.ini reader (section + key=value).
func parseINI(s string) map[string]map[string]string {
	out := map[string]map[string]string{}
	var cur string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = line[1 : len(line)-1]
			if _, ok := out[cur]; !ok {
				out[cur] = map[string]string{}
			}
			continue
		}
		if cur == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[cur][strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}
