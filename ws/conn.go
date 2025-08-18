package ws

import (
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	// Origin check opcional (coloque seu domínio em produção)
	CheckOrigin: func(r *http.Request) bool { return true },
}

type ClaimsProvider interface {
	FromRequest(r *http.Request) (tenantID, userID, role string, err error)
}

type wsConn struct {
	tenantID string
	userID   string
	role     string
	conn     *websocket.Conn
	hub      *Hub
}

func (c *wsConn) SendJSON(v any) error {
	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.conn.WriteJSON(v)
}
func (c *wsConn) Close() error     { return c.conn.Close() }
func (c *wsConn) TenantID() string { return c.tenantID }
func (c *wsConn) UserID() string   { return c.userID }

// Handler de upgrade: extrai claims, registra no hub e fica lendo ping/pong
func Serve(hub *Hub, claims ClaimsProvider, w http.ResponseWriter, r *http.Request) {
	tenantID, userID, role, err := claims.FromRequest(r)
	if err != nil {
		http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	wc := &wsConn{
		tenantID: tenantID,
		userID:   userID,
		role:     role,
		conn:     conn,
		hub:      hub,
	}
	hub.Add(wc)
	defer func() {
		hub.Remove(wc)
		_ = conn.Close()
	}()

	// mensagem de boas-vindas
	_ = wc.SendJSON(map[string]any{
		"type":     "ws.ready",
		"tenantId": tenantID,
		"userId":   userID,
		"role":     role,
		"ts":       time.Now().UTC(),
	})

	// Keep the connection alive; opcionalmente consuma mensagens do cliente
	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		// Se quiser processar mensagens do cliente, leia aqui
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}
