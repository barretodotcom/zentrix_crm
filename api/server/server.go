package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/barretodotcom/zentrix_crm/api/requests"
	"github.com/barretodotcom/zentrix_crm/api/utils"
	"github.com/barretodotcom/zentrix_crm/db"
	"github.com/barretodotcom/zentrix_crm/ws"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	DB             *pgxpool.Pool
	JwtSecret      []byte
	MetaAppID      string
	MetaSecret     string
	RedirectURI    string
	EvolutionUrl   string
	EvolutionToken string
	Hub            *ws.Hub
}

/* ==========================
   MODELOS / REQUISIÇÕES
========================== */

type createTenantReq struct {
	Name string `json:"name"`
}

type createTenantResp struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type createUserReq struct {
	TenantID string `json:"tenantId"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"` // "admin" | "user"
}

type createUserResp struct {
	ID        string    `json:"userId"`
	TenantID  string    `json:"tenantId"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"createdAt"`
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResp struct {
	Token    string `json:"token"`
	TenantID string `json:"tenantId"`
	UserID   string `json:"userId"`
	Role     string `json:"role"`
	Exp      int64  `json:"exp"`
}

type whatsappAccountReq struct {
	TenantID      string `json:"tenantId"`
	PhoneNumber   string `json:"phone_number,omitempty"`
	PhoneNumberID string `json:"phone_number_id"`
	WabaID        string `json:"waba_id"`
	AccessToken   string `json:"access_token"`
}

/* ==========================
   HANDLERS BÁSICOS
========================== */

func (s *Server) CreateTenant(w http.ResponseWriter, r *http.Request) {
	var req createTenantReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		utils.HttpError(w, http.StatusBadRequest, err.Error())
		return
	}

	var id string
	var created time.Time
	err := s.DB.QueryRow(r.Context(),
		`INSERT INTO tenants (name) VALUES ($1) RETURNING id, created_at`, req.Name).
		Scan(&id, &created)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 2️⃣ Se não existe, cria instância na Evolution
	instanceName := "tenant-" + req.Name + "-" + id[:8]
	payload := map[string]any{
		"instanceName": instanceName,
		"qrcode":       true,
		"webhook": map[string]any{
			"url":      "https://webhook.dev.zentrix.pro/webhook/message/receive",
			"byEvents": false,
			"base64":   true,
			"events":   []string{"MESSAGES_UPSERT"},
		},
		"integration": "WHATSAPP-BAILEYS",
		"token":       uuid.NewString(), // ou algum token específico por tenant
	}
	body, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	request, _ := http.NewRequest("POST", s.EvolutionUrl+"/instance/create", bytes.NewBuffer(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("apikey", s.EvolutionToken)

	resp, err := client.Do(request)
	if err != nil {
		utils.HttpError(w, http.StatusBadGateway, "evolution request error: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		utils.HttpError(w, resp.StatusCode, "evolution error: "+string(b))
		return
	}

	var evoResp struct {
		Instance struct {
			InstanceID string `json:"instanceId"`
		} `json:"instance"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&evoResp); err != nil {
		utils.HttpError(w, http.StatusInternalServerError, "invalid evolution response: "+err.Error())
		return
	}

	apiKey, err := s.FetchInstanceToken(evoResp.Instance.InstanceID)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, "invalid evolution response when fetching token: "+err.Error())
		return
	}

	// 3️⃣ Salva no Postgres
	_, err = s.DB.Exec(r.Context(),
		`INSERT INTO whatsapp_instances (tenant_id, instance_name, instance_id, api_key, qr_code, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
		id, instanceName, evoResp.Instance.InstanceID, apiKey, "", "disconnected",
	)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, "db insert error: "+err.Error())
		return
	}

	utils.JsonOK(w, createTenantResp{ID: id, Name: req.Name, CreatedAt: created})
}

func (s *Server) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.HttpError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.TenantID == "" || req.Email == "" || req.Password == "" {
		utils.HttpError(w, http.StatusBadRequest, "tenantId, email, password are required")
		return
	}
	if req.Role == "" {
		req.Role = "user"
	}

	// hash senha
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, "hash error")
		return
	}

	// valida tenant existe
	var dummy string
	if err := s.DB.QueryRow(r.Context(), `SELECT id FROM tenants WHERE id=$1`, req.TenantID).Scan(&dummy); err != nil {
		utils.HttpError(w, http.StatusBadRequest, err.Error())
		return
	}

	var id string
	var created time.Time
	err = s.DB.QueryRow(r.Context(),
		`INSERT INTO users (tenant_id, email, password_hash, role)
		 VALUES ($1,$2,$3,$4) RETURNING id, created_at`,
		req.TenantID, strings.ToLower(req.Email), string(hash), req.Role,
	).Scan(&id, &created)
	if err != nil {
		utils.HttpError(w, http.StatusConflict, fmt.Sprintf("create user: %v", err))
		return
	}

	exp := time.Now().Add(24 * time.Hour)
	tokenStr, err := s.SignJWT(req.TenantID, id, req.Role, exp)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, "jwt error")
		return
	}

	utils.JsonOK(w, createUserResp{
		ID: id, TenantID: req.TenantID, Email: strings.ToLower(req.Email), Role: req.Role, CreatedAt: created, Token: tokenStr,
	})
}

func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.HttpError(w, http.StatusBadRequest, "invalid body")
		return
	}
	var (
		userID   string
		tenantID string
		role     string
		passHash string
	)
	err := s.DB.QueryRow(r.Context(),
		`SELECT id, tenant_id, role, password_hash FROM users WHERE email=$1`,
		strings.ToLower(req.Email),
	).Scan(&userID, &tenantID, &role, &passHash)
	if err != nil {
		utils.HttpError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(passHash), []byte(req.Password)) != nil {
		utils.HttpError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	exp := time.Now().Add(24 * time.Hour)
	tokenStr, err := s.SignJWT(tenantID, userID, role, exp)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, "jwt error")
		return
	}

	utils.JsonOK(w, loginResp{
		Token: tokenStr, TenantID: tenantID, UserID: userID, Role: role, Exp: exp.Unix(),
	})
}

func (s *Server) SignJWT(tenantID, userID, role string, exp time.Time) (string, error) {
	claims := requests.Claims{
		TenantID: tenantID,
		UserID:   userID,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			Issuer:    "crm-api",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(s.JwtSecret)
}

type clientResp struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	TenantId        string     `json:"tenantId"`
	PhoneNumber     string     `json:"phoneNumber"`
	CreatedAt       time.Time  `json:"createdAt"`
	LastMessage     string     `json:"lastMessage"`
	UserId          *string    `json:"userId"`
	PictureUrl      *string    `json:"pictureUrl"`
	LastMessageDate *time.Time `json:"lastMessageDate,omitempty"`
}

type messageResp struct {
	ID         string    `json:"id"`
	TenantId   string    `json:"tenantId"`
	ClientId   string    `json:"clientId"`
	SenderRole string    `json:"senderRole"`
	Text       string    `json:"text"`
	CreatedAt  time.Time `json:"createdAt"`
}

func (s *Server) ListClients(w http.ResponseWriter, r *http.Request) {
	claims := requests.GetClaims(r)
	if claims == nil {
		utils.HttpError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	rows, err := s.DB.Query(r.Context(),
		`
		SELECT *
			FROM (
				SELECT DISTINCT ON (c.id)
					c.*,
					COALESCE(m.text, '') AS lastMessage,
					m.created_at AS lastMessageDate
				FROM clients c
				LEFT JOIN messages m 
					ON c.id = m.client_id
				WHERE c.tenant_id = $1
				ORDER BY c.id, m.created_at DESC
			) sub
		ORDER BY sub.lastMessageDate DESC NULLS LAST;
		`, claims.TenantID)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, "1: "+err.Error())
		return
	}
	defer rows.Close()

	clients := []clientResp{}
	for rows.Next() {
		var c clientResp
		if err := rows.Scan(&c.ID, &c.TenantId, &c.PhoneNumber, &c.Name, &c.CreatedAt, &c.UserId, &c.PictureUrl, &c.LastMessage, &c.LastMessageDate); err != nil {
			utils.HttpError(w, http.StatusInternalServerError, "2: "+err.Error())
			return
		}
		clients = append(clients, c)
	}

	utils.JsonOK(w, clients)
}

func (s *Server) ListClientsByUser(w http.ResponseWriter, r *http.Request) {
	claims := requests.GetClaims(r)
	if claims == nil {
		utils.HttpError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	rows, err := s.DB.Query(r.Context(),
		`
		SELECT *
			FROM (
				SELECT DISTINCT ON (c.id)
					c.*,
					COALESCE(m.text, '') AS lastMessage,
					m.created_at AS lastMessageDate
				FROM clients c
				LEFT JOIN messages m 
					ON c.id = m.client_id
				WHERE c.tenant_id = $1
				AND c.user_id = $2
				ORDER BY c.id, m.created_at DESC
			) sub
		ORDER BY sub.lastMessageDate DESC NULLS LAST;;
		`, claims.TenantID, claims.UserID)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, "1: "+err.Error())
		return
	}
	defer rows.Close()

	clients := []clientResp{}
	for rows.Next() {
		var c clientResp
		if err := rows.Scan(&c.ID, &c.TenantId, &c.PhoneNumber, &c.Name, &c.CreatedAt, &c.UserId, &c.PictureUrl, &c.LastMessage, &c.LastMessageDate); err != nil {
			utils.HttpError(w, http.StatusInternalServerError, "2: "+err.Error())
			return
		}
		clients = append(clients, c)
	}

	utils.JsonOK(w, clients)
}

func (s *Server) ListClientMessages(w http.ResponseWriter, r *http.Request) {
	claims := requests.GetClaims(r)
	if claims == nil {
		utils.HttpError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	clientId := chi.URLParam(r, "id")
	if clientId == "" {
		utils.HttpError(w, http.StatusBadRequest, "clientId is required")
		return
	}

	// Pega query params (com valores padrão)
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	page := 1
	limit := 20
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	offset := (page - 1) * limit

	rows, err := s.DB.Query(r.Context(),
		`SELECT id, tenant_id, client_id, sender_role, text, created_at
         FROM messages
         WHERE tenant_id=$1 AND client_id=$2
         ORDER BY created_at ASC
         LIMIT $3 OFFSET $4`,
		claims.TenantID, clientId, limit, offset)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	messages := []messageResp{}
	for rows.Next() {
		var m messageResp
		if err := rows.Scan(&m.ID, &m.TenantId, &m.ClientId, &m.SenderRole, &m.Text, &m.CreatedAt); err != nil {
			utils.HttpError(w, http.StatusInternalServerError, err.Error())
			return
		}
		messages = append(messages, m)
	}

	// Conta total de mensagens (pra saber quantas páginas existem)
	var total int
	err = s.DB.QueryRow(r.Context(),
		`SELECT COUNT(*) FROM messages WHERE tenant_id=$1 AND client_id=$2`,
		claims.TenantID, clientId).Scan(&total)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Retorna no formato paginado
	response := map[string]interface{}{
		"page":  page,
		"limit": limit,
		"total": total,
		"data":  messages,
	}

	utils.JsonOK(w, response)
}

/* ==========================
   META OAUTH (AUTOMAÇÃO)
========================== */

// GET /meta/oauth/start?tenant_id=...
// Redireciona o usuário para o consent da Meta
func (s *Server) MetaOAuthStart(w http.ResponseWriter, r *http.Request) {
	claims := requests.GetClaims(r)
	tenantID := claims.TenantID
	if tenantID == "" {
		utils.HttpError(w, http.StatusBadRequest, "tenant_id required")
		return
	}
	// checa se tenant existe
	var tmp string
	if err := s.DB.QueryRow(r.Context(), `SELECT id FROM tenants WHERE id=$1`, tenantID).Scan(&tmp); err != nil {
		utils.HttpError(w, http.StatusBadRequest, "tenant not found")
		return
	}

	state := utils.RandomState()
	// guarda state vinculado ao tenant (expira em 10 min)
	_, err := s.DB.Exec(r.Context(),
		`INSERT INTO oauth_states (state, tenant_id, created_at) VALUES ($1, $2, NOW())`, state, tenantID)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, "state persist error")
		return
	}

	// Monta URL de autorização
	// Doc oficial pode variar a cada versão; ajuste escopos conforme necessário
	authURL := fmt.Sprintf(
		"https://www.facebook.com/v20.0/dialog/oauth?client_id=%s&redirect_uri=%s&state=%s&scope=whatsapp_business_messaging,whatsapp_business_management",
		url.QueryEscape(s.MetaAppID),
		url.QueryEscape(s.RedirectURI),
		url.QueryEscape(state),
	)
	utils.JsonOK(w, map[string]string{"auth_url": authURL})
}

// GET /meta/oauth/callback?code=...&state=...
// Troca o code por access_token e salva em whatsapp_accounts do tenant
func (s *Server) MetaOAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		utils.HttpError(w, http.StatusBadRequest, "missing code/state")
		return
	}

	// valida state e obtém tenant
	var tenantID string
	err := s.DB.QueryRow(r.Context(),
		`SELECT tenant_id FROM oauth_states WHERE state=$1 AND created_at > NOW() - INTERVAL '10 minutes'`,
		state,
	).Scan(&tenantID)
	if err != nil {
		utils.HttpError(w, http.StatusBadRequest, "invalid or expired state")
		return
	}
	// apaga state (one-time use)
	_, _ = s.DB.Exec(r.Context(), `DELETE FROM oauth_states WHERE state=$1`, state)

	// Troca code -> access_token
	tokenURL := fmt.Sprintf(
		"https://graph.facebook.com/v20.0/oauth/access_token?client_id=%s&redirect_uri=%s&client_secret=%s&code=%s",
		url.QueryEscape(s.MetaAppID),
		url.QueryEscape(s.RedirectURI),
		url.QueryEscape(s.MetaSecret),
		url.QueryEscape(code),
	)
	// Chama Meta
	metaToken := struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}{}
	if err := utils.DoGETJSON(tokenURL, &metaToken); err != nil {
		utils.HttpError(w, http.StatusBadGateway, "failed to exchange code: "+err.Error())
		return
	}

	// Aqui normalmente você chamaria outros endpoints para obter:
	// - WhatsApp Business Account (WABA) vinculado
	// - phone_number_id
	// Isso varia conforme setup do cliente; para simplificar, deixo placeholders.
	// Você pode guiar o usuário a selecionar o número via UI e depois chamar POST /meta/whatsapp-account.
	// Depois de obter metaToken.AccessToken
	userAccounts := struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}{}

	// 1. Buscar contas do usuário
	if err := utils.DoGETJSON(
		fmt.Sprintf("https://graph.facebook.com/v20.0/me/accounts?access_token=%s", metaToken.AccessToken),
		&userAccounts,
	); err != nil {
		utils.HttpError(w, http.StatusBadGateway, "failed to fetch user accounts: "+err.Error())
		return
	}

	if len(userAccounts.Data) == 0 {
		utils.HttpError(w, http.StatusBadRequest, "nenhuma conta encontrada no Meta")
		return
	}

	// Pega a primeira conta (ou você pode pedir para o usuário escolher via UI)
	businessID := userAccounts.Data[0].ID

	// 2. Buscar WhatsApp Business Account vinculada
	businessInfo := struct {
		WhatsAppBusinessAccount struct {
			ID string `json:"id"`
		} `json:"whatsapp_business_account"`
	}{}

	if err := utils.DoGETJSON(
		fmt.Sprintf("https://graph.facebook.com/v20.0/%s?fields=whatsapp_business_account&access_token=%s",
			businessID, metaToken.AccessToken),
		&businessInfo,
	); err != nil {
		utils.HttpError(w, http.StatusBadGateway, "failed to fetch WABA: "+err.Error())
		return
	}

	wabaID := businessInfo.WhatsAppBusinessAccount.ID
	if wabaID == "" {
		utils.HttpError(w, http.StatusBadRequest, "nenhuma WABA vinculada")
		return
	}

	// 3. Buscar phone numbers do WABA
	phoneNumbers := struct {
		Data []struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
			Verified    string `json:"verified_name"`
		} `json:"data"`
	}{}

	if err := utils.DoGETJSON(
		fmt.Sprintf("https://graph.facebook.com/v20.0/%s/phone_numbers?access_token=%s",
			wabaID, metaToken.AccessToken),
		&phoneNumbers,
	); err != nil {
		utils.HttpError(w, http.StatusBadGateway, "failed to fetch phone numbers: "+err.Error())
		return
	}

	if len(phoneNumbers.Data) == 0 {
		utils.HttpError(w, http.StatusBadRequest, "nenhum número encontrado na WABA")
		return
	}

	// Pega o primeiro número (ou UI para escolher)
	phoneNumberID := phoneNumbers.Data[0].ID

	// Salva tudo no banco
	_, err = s.DB.Exec(r.Context(),
		`INSERT INTO whatsapp_accounts (tenant_id, phone_number, phone_number_id, waba_id, access_token, created_at, updated_at)
	 VALUES ($1,$2,$3,$4,$5, NOW(), NOW())
	 ON CONFLICT (tenant_id) DO UPDATE 
	   SET access_token=EXCLUDED.access_token, 
	       phone_number_id=EXCLUDED.phone_number_id, 
	       waba_id=EXCLUDED.waba_id,
	       updated_at=NOW()`,
		tenantID, phoneNumbers.Data[0].DisplayName, phoneNumberID, wabaID, metaToken.AccessToken,
	)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, "persist token: "+err.Error())
		return
	}

	utils.JsonOK(w, map[string]string{
		"status":          "ok",
		"message":         "WhatsApp conectado com sucesso!",
		"waba_id":         wabaID,
		"phone_number_id": phoneNumberID,
	})

}

func (s *Server) UpsertWhatsappAccount(w http.ResponseWriter, r *http.Request) {
	var req whatsappAccountReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.HttpError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.TenantID == "" || req.PhoneNumberID == "" || req.WabaID == "" || req.AccessToken == "" {
		utils.HttpError(w, http.StatusBadRequest, "missing fields")
		return
	}
	// garante tenant
	var ok string
	if err := s.DB.QueryRow(r.Context(), `SELECT id FROM tenants WHERE id=$1`, req.TenantID).Scan(&ok); err != nil {
		utils.HttpError(w, http.StatusBadRequest, "tenant not found")
		return
	}

	_, err := s.DB.Exec(r.Context(),
		`INSERT INTO whatsapp_accounts (tenant_id, phone_number, phone_number_id, waba_id, access_token, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,NOW(),NOW())
         ON CONFLICT (tenant_id) DO UPDATE
         SET phone_number=EXCLUDED.phone_number,
             phone_number_id=EXCLUDED.phone_number_id,
             waba_id=EXCLUDED.waba_id,
             access_token=EXCLUDED.access_token,
             updated_at=NOW()`,
		req.TenantID, req.PhoneNumber, req.PhoneNumberID, req.WabaID, req.AccessToken,
	)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	utils.JsonOK(w, map[string]string{"status": "ok"})
}

func (s *Server) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			utils.HttpError(w, http.StatusUnauthorized, "missing or invalid Authorization header")
			return
		}

		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.ParseWithClaims(tokenStr, &requests.Claims{}, func(token *jwt.Token) (interface{}, error) {
			return s.JwtSecret, nil
		})
		if err != nil || !token.Valid {
			utils.HttpError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		claims := token.Claims.(*requests.Claims)
		// salva no contexto para handlers acessarem
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) RequireAuthWebSocket(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Token")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			utils.HttpError(w, http.StatusUnauthorized, "missing or invalid Authorization header")
			return
		}

		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.ParseWithClaims(tokenStr, &requests.Claims{}, func(token *jwt.Token) (interface{}, error) {
			return s.JwtSecret, nil
		})
		if err != nil || !token.Valid {
			utils.HttpError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		claims := token.Claims.(*requests.Claims)
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type IncomingMessage struct {
	TenantID string                 `json:"tenantId"`
	Type     string                 `json:"type"`
	Payload  IncomingMessagePayload `json:"payload"`
}

type IncomingMessagePayload struct {
	ClientId   string    `json:"clientId"`
	Text       string    `json:"text"`
	From       string    `json:"from"`
	Name       string    `json:"name"`
	SenderRole string    `json:"senderRole"`
	CreatedAt  time.Time `json:"createdAt"`
}

// payload WS
type WSMessage struct {
	Type       string          `json:"type"`
	ClientId   string          `json:"clientId"`
	TenantID   string          `json:"tenantId"`
	SenderRole string          `json:"senderRole"`
	Data       IncomingMessage `json:"data"`
}

func (s *Server) IncomingMessage(w http.ResponseWriter, r *http.Request) {
	// segurança simples pro webhook do n8n
	secret := os.Getenv("N8N_WEBHOOK_SECRET")
	if secret == "" {
		secret = "dev-secret"
	}
	if r.Header.Get("X-Webhook-Secret") != secret {
		utils.HttpError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var msg IncomingMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		utils.HttpError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if msg.TenantID == "" {
		utils.HttpError(w, http.StatusBadRequest, "tenantId is required")
		return
	}

	fmt.Println(msg.TenantID)
	event := WSMessage{
		Type:       msg.Type,
		TenantID:   msg.TenantID,
		ClientId:   msg.Payload.ClientId,
		SenderRole: msg.Payload.SenderRole,
		Data:       msg,
	}

	s.Hub.Broadcast(ws.BroadcastOpts{
		TenantID: msg.TenantID,
	}, event)

	utils.JsonOK(w, map[string]string{"status": "ok"})
}

type sendMessageReq struct {
	TenantID string `json:"tenantId"`
	ClientID string `json:"clientId"`
	Message  string `json:"message"`
}

type whatsappSendPayload struct {
	Token        string `json:"token"`
	To           string `json:"to"`
	Type         string `json:"type"`
	Text         string `json:"text"`
	ClientId     string `json:"clientId"`
	TenantId     string `json:"tenantId"`
	InstanceName string `json:"instanceName"`
}

func (s *Server) SendMessage(w http.ResponseWriter, r *http.Request) {
	var req sendMessageReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.HttpError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.ClientID == "" || req.Message == "" {
		utils.HttpError(w, http.StatusBadRequest, "client_id and message are required")
		return
	}

	var c db.Client
	fmt.Println(req.ClientID)
	err := s.DB.QueryRow(context.TODO(),
		`SELECT id, tenant_id, phone_number, name, created_at
         FROM clients
         WHERE id=$1`,
		req.ClientID,
	).Scan(&c.ID, &c.TenantId, &c.PhoneNumber, &c.Name, &c.CreatedAt)
	if err != nil {
		utils.HttpError(w, http.StatusBadRequest, err.Error())
		return
	}
	// var wa db.WhatsappAccount

	// err = s.DB.QueryRow(context.TODO(),
	// 	`SELECT access_token
	//      FROM whatsapp_accounts
	//      WHERE tenant_id=$1`,
	// 	c.TenantId,
	// ).Scan(&wa.AccessToken)
	// if err != nil {
	// 	utils.HttpError(w, http.StatusBadRequest, err.Error())
	// 	return
	// }

	var apiKey string
	var instanceName string
	err = s.DB.QueryRow(context.TODO(),
		`SELECT api_key, instance_name
         FROM whatsapp_instances
         WHERE tenant_id=$1`,
		c.TenantId,
	).Scan(&apiKey, &instanceName)
	if err != nil {
		utils.HttpError(w, http.StatusBadRequest, err.Error())
		return
	}

	payload := whatsappSendPayload{
		Token:        apiKey,
		To:           c.PhoneNumber + "@s.whatsapp.net",
		Type:         "text",
		Text:         req.Message,
		ClientId:     c.ID,
		TenantId:     c.TenantId,
		InstanceName: instanceName,
	}

	body, _ := json.Marshal(payload)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Post(
		"https://webhook.dev.zentrix.pro/webhook/KfjISedLsPHOMmC5/enviar-mensagens/whatsapp-send",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, "failed to send message: "+err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		utils.HttpError(w, http.StatusInternalServerError, "webhook error: "+string(respBody))
		return
	}

	utils.JsonOK(w, map[string]string{"status": "sent"})
}

func (s *Server) GetWhatsAppQRCode(w http.ResponseWriter, r *http.Request) {
	claims := requests.GetClaims(r)
	if claims == nil {
		utils.HttpError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	tenantID := claims.TenantID

	type evoReq struct {
		Action   string `json:"action"`
		TenantID string `json:"tenantId"`
	}

	var instanceName string
	err := s.DB.QueryRow(r.Context(),
		`SELECT instance_name FROM whatsapp_instances WHERE tenant_id=$1`,
		tenantID,
	).Scan(&instanceName)
	if err != nil {
		utils.HttpError(w, http.StatusBadRequest, "instance not found for tenant")
		return
	}
	fmt.Println(instanceName)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", s.EvolutionUrl+"/instance/connect/"+instanceName, nil)
	if err != nil {
		utils.HttpError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Token da sua instância Evolution
	req.Header.Set("apiKey", s.EvolutionToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		utils.HttpError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		utils.HttpError(w, resp.StatusCode, "evolution error: "+string(b))
		return
	}

	// Recebe JSON com QR Code base64
	var evoResp struct {
		Code   string `json:"code"` // exemplo: "data:image/png;base64,..."
		Base64 string `json:"base64"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&evoResp); err != nil {
		utils.HttpError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Retorna para o frontend
	utils.JsonOK(w, evoResp)
}

func (s *Server) FetchInstanceToken(instanceID string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET",
		s.EvolutionUrl+"/instance/fetchInstances?instanceId="+instanceID,
		nil)
	if err != nil {
		fmt.Println(err.Error() + " - FetchInstanceToken")
		return "", err
	}

	req.Header.Set("accept", "application/json, text/plain, */*")
	req.Header.Set("apikey", s.EvolutionToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		fmt.Println(err.Error() + " - statuscode")
		return "", fmt.Errorf("evolution error: %s", string(b))
	}
	type EvoInstance struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}

	var evoResp []EvoInstance
	if err := json.NewDecoder(resp.Body).Decode(&evoResp); err != nil {
		fmt.Println(err.Error() + " - decoding")
		println("error decoding evolution response:", err.Error())
		return "", err
	}

	if len(evoResp) == 0 {
		println("nenhuma instância encontrada")
		return "", fmt.Errorf("nenhuma instância encontrada")
	}
	return evoResp[0].Token, nil
}
