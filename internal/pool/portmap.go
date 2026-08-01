package pool

import (
	"encoding/json"
	"os"
	"sort"

	"fxpool-proxy/internal/securefile"
	"fxpool-proxy/internal/serverlist"
)

type Ports struct {
	Socks    int    `json:"socks"`
	HTTP     int    `json:"http"`
	Country  string `json:"country,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}
type portFile struct {
	Version     int              `json:"version"`
	SocksBase   int              `json:"socks_base"`
	HTTPBase    int              `json:"http_base"`
	Assignments map[string]Ports `json:"assignments"`
}

func AssignPorts(path string, nodes []serverlist.Node, socksBase, httpBase int) (map[string]Ports, error) {
	p := portFile{1, socksBase, httpBase, map[string]Ports{}}
	if b, e := securefile.ReadRegular(path, 4<<20, false); e == nil {
		var old portFile
		if json.Unmarshal(b, &old) == nil && old.Version == 1 && old.SocksBase == socksBase && old.HTTPBase == httpBase && old.Assignments != nil {
			p.Assignments = old.Assignments
		}
	}
	usedS, usedH := map[int]bool{}, map[int]bool{}
	valid := map[string]Ports{}
	for k, v := range p.Assignments {
		if v.Socks >= socksBase && v.Socks <= 65535 && v.HTTP >= httpBase && v.HTTP <= 65535 && !usedS[v.Socks] && !usedH[v.HTTP] {
			valid[k] = v
			usedS[v.Socks] = true
			usedH[v.HTTP] = true
		}
	}
	p.Assignments = valid
	sorted := append([]serverlist.Node(nil), nodes...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].StableID() < sorted[j].StableID() })
	next := func(base int, used map[int]bool) int {
		for x := base; x <= 65535; x++ {
			if !used[x] {
				used[x] = true
				return x
			}
		}
		return 0
	}
	out := map[string]Ports{}
	for _, n := range sorted {
		id := n.StableID()
		v, ok := p.Assignments[id]
		if !ok {
			v = Ports{next(socksBase, usedS), next(httpBase, usedH), n.Country, n.Hostname}
			if v.Socks == 0 || v.HTTP == 0 {
				return nil, os.ErrInvalid
			}
			p.Assignments[id] = v
		}
		out[id] = v
	}
	if e := securefile.AtomicJSON(path, p, 0o644); e != nil {
		return nil, e
	}
	return out, nil
}
