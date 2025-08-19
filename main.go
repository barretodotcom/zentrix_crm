package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/barretodotcom/zentrix_crm/api/requests"
	"github.com/barretodotcom/zentrix_crm/api/server"
	"github.com/barretodotcom/zentrix_crm/ws"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

func init() {
	godotenv.Load()
}

func main() {
	// ENV esperadas:
	// DATABASE_URL=postgres://user:pass@localhost:5432/db?sslmode=disable
	// JWT_SECRET=supersecret
	// META_APP_ID=...
	// META_APP_SECRET=...
	// META_REDIRECT_URI=https://seusistema.com/meta/oauth/callback
	dbURL := mustEnv("DATABASE_URL")
	jwtSecret := []byte(mustEnv("JWT_SECRET"))
	metaAppID := mustEnv("META_APP_ID")
	metaSecret := mustEnv("META_APP_SECRET")
	redirectURI := mustEnv("META_REDIRECT_URI")

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("db pool: %v", err)
	}

	s := &server.Server{
		DB:          pool,
		JwtSecret:   jwtSecret,
		MetaAppID:   metaAppID,
		MetaSecret:  metaSecret,
		RedirectURI: redirectURI,
		Hub:         ws.NewHub(),
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Logger, middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, // ou colocar os domínios específicos do frontend
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300, // cache do preflight em segundos
	}))

	claimsProv := requests.ClaimsProvider{Secret: jwtSecret}

	// Público
	r.Route(("/api"), func(r chi.Router) {
		r.Use(middleware.AllowContentType("application/json"))
		r.Post("/tenants", s.CreateTenant)
		r.Post("/users", s.CreateUser)
		r.Post("/auth/login", s.Login)

		// endpoint interno (n8n -> backend -> WS)
		r.Post("/internal/messages/incoming", s.IncomingMessage)

		r.Group(func(r chi.Router) {
			r.Use(s.RequireAuth)
			r.Get("/clients", s.ListClients)
			r.Get("/client/messages/{id}", s.ListClientMessages)
			r.Get("/meta/oauth/start", s.MetaOAuthStart)
			r.Get("/meta/oauth/callback", s.MetaOAuthCallback)

			r.Post("/meta/whatsapp-account", s.UpsertWhatsappAccount)

			// endpoint externo (frontend -> backend -> n8n)
			r.Post("/messages/send", s.SendMessage)
		})
	})

	r.Group(func(r chi.Router) {
		r.Get("/api/ws", func(w http.ResponseWriter, r *http.Request) {
			ws.Serve(s.Hub, claimsProv, w, r)
		})
	})

	addr := ":8081"
	log.Printf("API up at %s", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing env %s", k)
	}
	return v
}
