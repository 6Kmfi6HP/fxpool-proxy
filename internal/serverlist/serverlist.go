package serverlist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"fxpool-proxy/internal/securefile"
)

const DefaultURL = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"
const DefaultFirefoxVersion = "155.0a1"

type Node struct {
	Country           string `json:"country"`
	CountryName       string `json:"country_name"`
	City              string `json:"city"`
	CityName          string `json:"city_name"`
	Hostname          string `json:"hostname"`
	Port              int    `json:"port"`
	Protocol          string `json:"protocol"`
	Scheme            string `json:"scheme"`
	Locked            bool   `json:"locked"`
	Supported         bool   `json:"supported"`
	UnsupportedReason string `json:"unsupported_reason,omitempty"`
	RecordID          string `json:"record_id"`
	FilterExpression  string `json:"filter_expression,omitempty"`
	LastModified      int64  `json:"last_modified,omitempty"`
	FilterMatched     bool   `json:"filter_matched"`
}

func (n Node) StableID() string {
	return fmt.Sprintf("%s:%s:%s:%s:%d:%s", n.RecordID, strings.ToUpper(n.Country), strings.ToUpper(n.City), strings.ToLower(n.Hostname), n.Port, strings.ToLower(n.Protocol))
}

var versionRE = regexp.MustCompile(`^\s*(\d+(?:\.\d+)*)(?:(a|b|rc)(\d+)?)?\s*$`)
var versionTerm = regexp.MustCompile(`^env\.version\|versionCompare\("([0-9A-Za-z.]+)"\)\s*(>=|<=|==|!=|>|<)\s*0$`)
var countryTerm = regexp.MustCompile(`^env\.country\s*(==|!=)\s*"([A-Za-z]{2,3})"$`)

type version struct {
	nums      []int
	rank, pre int
}

func parseVersion(s string) (version, error) {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return version{}, fmt.Errorf("unsupported Firefox version: %q", s)
	}
	v := version{}
	for _, p := range strings.Split(m[1], ".") {
		n, _ := strconv.Atoi(p)
		v.nums = append(v.nums, n)
	}
	v.rank = map[string]int{"a": 0, "b": 1, "rc": 2, "": 3}[strings.ToLower(m[2])]
	v.pre, _ = strconv.Atoi(m[3])
	return v, nil
}
func CompareVersions(a, b string) (int, error) {
	x, e := parseVersion(a)
	if e != nil {
		return 0, e
	}
	y, e := parseVersion(b)
	if e != nil {
		return 0, e
	}
	w := max(len(x.nums), len(y.nums))
	for i := 0; i < w; i++ {
		xn, yn := 0, 0
		if i < len(x.nums) {
			xn = x.nums[i]
		}
		if i < len(y.nums) {
			yn = y.nums[i]
		}
		if xn < yn {
			return -1, nil
		}
		if xn > yn {
			return 1, nil
		}
	}
	if x.rank < y.rank {
		return -1, nil
	}
	if x.rank > y.rank {
		return 1, nil
	}
	if x.pre < y.pre {
		return -1, nil
	}
	if x.pre > y.pre {
		return 1, nil
	}
	return 0, nil
}
func Evaluate(expr, firefoxVersion, country string) bool {
	if strings.TrimSpace(expr) == "" {
		return true
	}
	for _, raw := range strings.Split(expr, "&&") {
		term := strings.TrimSpace(raw)
		if m := versionTerm.FindStringSubmatch(term); m != nil {
			c, e := CompareVersions(firefoxVersion, m[1])
			if e != nil || !compare(c, m[2]) {
				return false
			}
			continue
		}
		if m := countryTerm.FindStringSubmatch(term); m != nil {
			eq := strings.EqualFold(country, m[2])
			if (m[1] == "==") != eq {
				return false
			}
			continue
		}
		return false
	}
	return true
}
func compare(v int, op string) bool {
	switch op {
	case ">=":
		return v >= 0
	case "<=":
		return v <= 0
	case "==":
		return v == 0
	case "!=":
		return v != 0
	case ">":
		return v > 0
	case "<":
		return v < 0
	}
	return false
}

type protocol struct {
	Protocol string `json:"protocol"`
	Name     string `json:"name"`
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
}
type server struct {
	Hostname    string     `json:"hostname"`
	Port        int        `json:"port"`
	Quarantined bool       `json:"quarantined"`
	Locked      bool       `json:"locked"`
	Protocols   []protocol `json:"protocols"`
}
type city struct {
	Code    string   `json:"code"`
	Name    string   `json:"name"`
	Locked  bool     `json:"locked"`
	Servers []server `json:"servers"`
}
type record struct {
	ID           string `json:"id"`
	Code         string `json:"code"`
	Name         any    `json:"name"`
	Filter       string `json:"filter_expression"`
	Locked       bool   `json:"locked"`
	LastModified int64  `json:"last_modified"`
	Cities       []city `json:"cities"`
}
type envelope struct {
	Data []record `json:"data"`
}

func Parse(raw []byte, firefoxVersion, country string, includeLocked bool) ([]Node, error) {
	var e envelope
	if err := json.Unmarshal(raw, &e); err != nil || e.Data == nil {
		var records []record
		if err2 := json.Unmarshal(raw, &records); err2 != nil {
			return nil, errors.New("vpn-serverlist data must be a list")
		}
		e.Data = records
	}
	var out []Node
	seen := map[string]bool{}
	for _, r := range e.Data {
		eligible := Evaluate(r.Filter, firefoxVersion, country)
		rlocked := r.Locked || !eligible
		if rlocked && !includeLocked {
			continue
		}
		countryName := r.Code
		if s, ok := r.Name.(string); ok && s != "" {
			countryName = s
		}
		for _, c := range r.Cities {
			clocked := rlocked || c.Locked
			if clocked && !includeLocked {
				continue
			}
			for _, s := range c.Servers {
				locked := clocked || s.Locked
				if s.Quarantined || (locked && !includeLocked) {
					continue
				}
				host, port, proto, scheme, supported, reason := selectProtocol(s)
				if net.ParseIP(host) == nil && !validDNS(host) {
					continue
				}
				if host == "" || port < 1 || port > 65535 {
					continue
				}
				n := Node{strings.ToUpper(r.Code), countryName, c.Code, c.Name, strings.ToLower(host), port, proto, scheme, locked, supported, reason, r.ID, r.Filter, r.LastModified, eligible}
				if !seen[n.StableID()] {
					seen[n.StableID()] = true
					out = append(out, n)
				}
			}
		}
	}
	return out, nil
}
func selectProtocol(s server) (string, int, string, string, bool, string) {
	port := s.Port
	if port == 0 {
		port = 443
	}
	if len(s.Protocols) == 0 {
		return s.Hostname, port, "connect", "https", true, ""
	}
	for _, p := range s.Protocols {
		name := strings.ToLower(first(p.Protocol, p.Name))
		if name == "connect" {
			host := first(p.Host, p.Hostname, s.Hostname)
			pp := p.Port
			if pp == 0 {
				pp = port
			}
			scheme := first(p.Scheme, "https")
			if !strings.EqualFold(scheme, "https") {
				return host, pp, name, scheme, false, "unsupported CONNECT scheme: " + scheme
			}
			return host, pp, name, strings.ToLower(scheme), true, ""
		}
	}
	p := s.Protocols[0]
	name := strings.ToLower(first(p.Protocol, p.Name, "unknown"))
	host := first(p.Host, p.Hostname, s.Hostname)
	pp := p.Port
	if pp == 0 {
		pp = port
	}
	return host, pp, name, first(p.Scheme, "https"), false, "unsupported upstream protocol chain (first available: " + name + ")"
}
func first(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
func validDNS(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, p := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if p == "" || len(p) > 63 || strings.HasPrefix(p, "-") || strings.HasSuffix(p, "-") {
			return false
		}
		for _, r := range p {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

type Store struct {
	URL, CachePath, MetaPath string
	Client                   *http.Client
}
type metadata struct {
	Version             int     `json:"version"`
	URL                 string  `json:"url"`
	ETag                string  `json:"etag,omitempty"`
	LastModified        string  `json:"last_modified,omitempty"`
	FetchedAt           float64 `json:"fetched_at"`
	LastSuccessfulParse float64 `json:"last_successful_parse"`
	FirefoxVersion      string  `json:"firefox_version"`
	ClientCountry       string  `json:"client_country"`
}

func (s Store) Fetch(ctx context.Context, force bool, firefoxVersion, country string, includeLocked bool) ([]Node, error) {
	cached, _ := securefile.ReadRegular(s.CachePath, 8<<20, false)
	var m metadata
	if b, e := securefile.ReadRegular(s.MetaPath, 1<<20, false); e == nil {
		_ = json.Unmarshal(b, &m)
	}
	parse := func(b []byte) ([]Node, error) {
		n, e := Parse(b, firefoxVersion, country, includeLocked)
		if e != nil {
			return nil, e
		}
		for _, v := range n {
			if v.Supported && !v.Locked {
				return n, nil
			}
		}
		return nil, errors.New("vpn-serverlist contains no usable CONNECT nodes")
	}
	if !force && len(cached) > 0 && time.Since(time.Unix(int64(m.FetchedAt), 0)) < time.Hour {
		if n, e := parse(cached); e == nil {
			return n, nil
		}
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "firefox-ip-protection-pool/3.0")
	if m.ETag != "" {
		req.Header.Set("If-None-Match", m.ETag)
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, e := client.Do(req)
	if e != nil {
		if len(cached) > 0 {
			return parse(cached)
		}
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		n, e := parse(cached)
		if e == nil {
			m.FetchedAt = float64(time.Now().Unix())
			_ = securefile.AtomicJSON(s.MetaPath, m, 0o644)
		}
		return n, e
	}
	if resp.StatusCode != 200 {
		if len(cached) > 0 {
			return parse(cached)
		}
		return nil, fmt.Errorf("serverlist HTTP %d", resp.StatusCode)
	}
	var raw json.RawMessage
	if e = json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 8<<20)).Decode(&raw); e != nil {
		return nil, e
	}
	n, e := parse(raw)
	if e != nil {
		if len(cached) > 0 {
			return parse(cached)
		}
		return nil, e
	}
	now := float64(time.Now().Unix())
	m = metadata{1, s.URL, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), now, now, firefoxVersion, country}
	if e = securefile.AtomicWrite(s.CachePath, append(raw, '\n'), 0o644); e != nil {
		return nil, e
	}
	if e = securefile.AtomicJSON(s.MetaPath, m, 0o644); e != nil {
		return nil, e
	}
	sort.Slice(n, func(i, j int) bool { return n[i].StableID() < n[j].StableID() })
	return n, nil
}
func DefaultStore(root, url string) Store {
	if url == "" {
		url = DefaultURL
	}
	return Store{URL: url, CachePath: root + "/data/vpn-serverlist.json", MetaPath: root + "/data/vpn-serverlist.meta.json"}
}

var _ = os.ErrNotExist
