package registry

import (
	"fmt"
	"sithukyaw666/tunnel/internal/transport"
	"sync"
)

type Registry struct {
	mu       sync.RWMutex
	Sessions map[string]transport.Session
}

func NewRegistry() *Registry {
	return &Registry{
		Sessions: make(map[string]transport.Session),
	}
}

func (r *Registry) AddSession(hostname string, s transport.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Sessions[hostname] = s
}

func (r *Registry) GetSession(hostname string) (transport.Session, error) {
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
