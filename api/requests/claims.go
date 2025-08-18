package requests

import (
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	TenantID string `json:"tenantId"`
	UserID   string `json:"userId"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

type ClaimsProvider struct {
	Secret []byte
}

func GetClaims(r *http.Request) *Claims {
	if c, ok := r.Context().Value("claims").(*Claims); ok {
		return c
	}
	return nil
}

// Extrai JWT de Authorization: Bearer <token> OU query ?token=...
func (p ClaimsProvider) FromRequest(r *http.Request) (tenantID, userID, role string, err error) {
	tokenStr := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		tokenStr = strings.TrimPrefix(auth, "Bearer ")
	}
	if tokenStr == "" {
		tokenStr = r.URL.Query().Get("token")
	}
	if tokenStr == "" {
		return "", "", "", errors.New("missing token")
	}

	tok, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		return p.Secret, nil
	})
	if err != nil || !tok.Valid {
		return "", "", "", errors.New("invalid token")
	}
	cl := tok.Claims.(*Claims)
	return cl.TenantID, cl.UserID, cl.Role, nil
}
