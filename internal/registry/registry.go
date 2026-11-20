package registry

import (
	"fmt"
	"sync"

	"github.com/hashicorp/yamux"
)

type Registry struct {
	mu       sync.RWMutex
	Sessions map[string]*yamux.Session
}

func NewRegistry() *Registry {
	return &Registry{
		Sessions: make(map[string]*yamux.Session),
	}
}

func (r *Registry) AddSession(hostname string, s *yamux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Sessions[hostname] = s
}

func (r *Registry) GetSession(hostname string) (*yamux.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.Sessions[hostname]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("no session found with that hostname: %s", hostname)
}

func (r *Registry) RemoveSession(hostname string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.Sessions[hostname]; ok {
		delete(r.Sessions, hostname)
		return nil
	}
	return fmt.Errorf("no session found with that hostname: %s", hostname)

}
