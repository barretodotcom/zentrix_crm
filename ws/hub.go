package ws

import (
	"sync"
)

type Conn interface {
	SendJSON(v any) error
	Close() error
	UserID() string
	TenantID() string
}

type Hub struct {
	// tenantID -> userID -> set(conns)
	tenants map[string]map[string]map[Conn]struct{}
	mu      sync.RWMutex
}

func NewHub() *Hub {
	return &Hub{
		tenants: make(map[string]map[string]map[Conn]struct{}),
	}
}

func (h *Hub) Add(c Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	tid, uid := c.TenantID(), c.UserID()
	if h.tenants[tid] == nil {
		h.tenants[tid] = make(map[string]map[Conn]struct{})
	}
	if h.tenants[tid][uid] == nil {
		h.tenants[tid][uid] = make(map[Conn]struct{})
	}
	h.tenants[tid][uid][c] = struct{}{}
}

func (h *Hub) Remove(c Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	tid, uid := c.TenantID(), c.UserID()
	if h.tenants[tid] == nil || h.tenants[tid][uid] == nil {
		return
	}
	delete(h.tenants[tid][uid], c)
	if len(h.tenants[tid][uid]) == 0 {
		delete(h.tenants[tid], uid)
	}
	if len(h.tenants[tid]) == 0 {
		delete(h.tenants, tid)
	}
}

type BroadcastOpts struct {
	TenantID string
	UserIDs  []string // opcional; vazio => todos do tenant
}

func (h *Hub) Broadcast(opts BroadcastOpts, payload any) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	bucket, ok := h.tenants[opts.TenantID]
	if !ok {
		return
	}

	sendToSet := func(set map[Conn]struct{}) {
		for c := range set {
			_ = c.SendJSON(payload) // ignoramos erro de write quebrado; cleanup ao fechar
		}
	}

	if len(opts.UserIDs) == 0 {
		for _, set := range bucket {
			sendToSet(set)
		}
		return
	}
	for _, uid := range opts.UserIDs {
		if set, ok := bucket[uid]; ok {
			sendToSet(set)
		}
	}
}
