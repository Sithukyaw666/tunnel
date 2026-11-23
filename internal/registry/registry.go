package registry

import (
	"fmt"
	"sithukyaw666/tunnel/internal/transport"
	"sync"
)

type Registry struct {
	mu       sync.RWMutex
	sessions map[string]transport.Session
}

func NewRegistry() *Registry {
	return &Registry{
		sessions: make(map[string]transport.Session),
	}
}

func (r *Registry) ListSessions() map[string]transport.Session {
	return r.sessions
}

func (r *Registry) AddSession(hostname string, s transport.Session) (old transport.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old = r.sessions[hostname]
	r.sessions[hostname] = s
	return old
}

func (r *Registry) GetSession(hostname string) (transport.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if t, ok := r.sessions[hostname]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("no session found with that hostname: %s", hostname)
}

func (r *Registry) RemoveSession(hostname string, s transport.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current, ok := r.sessions[hostname]; ok && current == s {
		delete(r.sessions, hostname)
		return nil
	}
	return fmt.Errorf("no session found with that hostname: %s", hostname)

}
