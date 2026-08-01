package pool

import (
	"errors"
	"fxpool-proxy/internal/serverlist"
	"math/rand/v2"
	"sync"
)

type Selector struct {
	mu           sync.Mutex
	Nodes        map[string][]serverlist.Node
	Mode         string
	countryIndex map[string]int
	global       int
}

func NewSelector(nodes []serverlist.Node, mode string) *Selector {
	s := &Selector{Nodes: map[string][]serverlist.Node{}, Mode: mode, countryIndex: map[string]int{}}
	for _, n := range nodes {
		if n.Supported && !n.Locked && n.Country != "REC" {
			s.Nodes[n.Country] = append(s.Nodes[n.Country], n)
		}
	}
	return s
}
func (s *Selector) Choose(exclude map[string]bool) (serverlist.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var countries []string
	for c, ns := range s.Nodes {
		for _, n := range ns {
			if !exclude[n.StableID()] {
				countries = append(countries, c)
				break
			}
		}
	}
	if len(countries) == 0 {
		return serverlist.Node{}, errors.New("no upstream nodes available")
	}
	var country string
	if s.Mode == "rr" {
		country = countries[s.global%len(countries)]
		s.global++
	} else {
		country = countries[rand.IntN(len(countries))]
	}
	var available []serverlist.Node
	for _, n := range s.Nodes[country] {
		if !exclude[n.StableID()] {
			available = append(available, n)
		}
	}
	if s.Mode == "rr" {
		i := s.countryIndex[country] % len(available)
		s.countryIndex[country]++
		return available[i], nil
	}
	return available[rand.IntN(len(available))], nil
}
