package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

// AuthConfig holds the authentication configuration.
type AuthConfig struct {
	Enabled bool
	Keys    map[string]string // key -> description
	mu      sync.RWMutex
}

func isPublicCapabilitiesRequest(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.Path == "/api/capabilities"
}

func isPublicObservabilityRequest(r *http.Request) bool {
	return r.Method == http.MethodGet && (r.URL.Path == "/health" || r.URL.Path == "/metrics")
}

// isDataPlaneBlobRequest reports whether a request targets the
// capability-authenticated blob endpoints.
//
// Those endpoints do NOT bypass authorization. They carry their own,
// which is strictly narrower than a session: a signed capability bound
// to one object, one attempt and one fencing generation, checked against
// a tenant the request never supplies. What they bypass is the
// requirement to be a SESSION, because a worker cannot produce one and
// holds an opaque token instead (see blobAuth).
//
// Matched by shape rather than by prefix so this can never widen: three
// methods, a fixed six-segment path under /api/runs, and nothing else.
func isDataPlaneBlobRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodPut, http.MethodPost:
	default:
		return false
	}
	p := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// api runs {runID} nodes {nodeID} attempts {attempt} blobs [objectID]
	if len(p) < 8 || len(p) > 9 {
		return false
	}
	return p[0] == "api" && p[1] == "runs" && p[3] == "nodes" &&
		p[5] == "attempts" && p[7] == "blobs"
}

func withPublicAuthBypass(middleware func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		protected := middleware(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isPublicCapabilitiesRequest(r) || isPublicObservabilityRequest(r) || isDataPlaneBlobRequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			protected.ServeHTTP(w, r)
		})
	}
}

// NewAuthConfig creates an auth config. If no keys provided, auth is disabled.
func NewAuthConfig() *AuthConfig {
	return &AuthConfig{
		Keys: make(map[string]string),
	}
}

// AddKey registers an API key.
func (a *AuthConfig) AddKey(key, description string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Keys[key] = description
	a.Enabled = true
}

// RemoveKey removes an API key.
func (a *AuthConfig) RemoveKey(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.Keys, key)
	if len(a.Keys) == 0 {
		a.Enabled = false
	}
}

// ValidateKey checks if a key is valid using constant-time comparison.
func (a *AuthConfig) ValidateKey(key string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for k := range a.Keys {
		if subtle.ConstantTimeCompare([]byte(k), []byte(key)) == 1 {
			return true
		}
	}
	return false
}

// Describe returns the registered description for a valid key (its
// AddKey label, e.g. "CLI-provided key"), or "" if the key doesn't match.
// Constant-time for the same reason ValidateKey is.
func (a *AuthConfig) Describe(key string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for k, desc := range a.Keys {
		if subtle.ConstantTimeCompare([]byte(k), []byte(key)) == 1 {
			return desc
		}
	}
	return ""
}

// GenerateKey creates a cryptographically secure API key.
func GenerateKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "brk_" + hex.EncodeToString(b), nil
}

// APIKeyAuth is middleware that enforces API key authentication.
// Skips auth for UI routes (non-/api paths) and WebSocket upgrades.
func APIKeyAuth(auth *AuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isPublicCapabilitiesRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Skip if auth is disabled
			if !auth.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Skip non-API routes (UI serving)
			if !strings.HasPrefix(r.URL.Path, "/api/") {
				next.ServeHTTP(w, r)
				return
			}

			// WebSocket — let JWT middleware handle auth
			if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
				next.ServeHTTP(w, r)
				return
			}

			// Skip webhook triggers (own token auth)
			if strings.Contains(r.URL.Path, "/webhook") && r.Method == "POST" {
				next.ServeHTTP(w, r)
				return
			}

			// Check Authorization header: "Bearer brk_..."
			authHeader := r.Header.Get("Authorization")
			key := ""
			if strings.HasPrefix(authHeader, "Bearer ") {
				key = strings.TrimPrefix(authHeader, "Bearer ")
			}

			// Also accept X-API-Key header
			if key == "" {
				key = r.Header.Get("X-API-Key")
			}

			if key == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "API key required"})
				return
			}

			if !auth.ValidateKey(key) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid API key"})
				return
			}

			// A validated static key is a complete identity on its own --
			// stamp admin-equivalent claims into the context so JWTAuth
			// (the next middleware in the chain) recognizes the request as
			// already authenticated instead of demanding a JWT that a
			// static key was never going to produce. Without this, the
			// static key only ever unlocked /api/auth/* (to bootstrap the
			// first user); every real resource route -- /api/pipelines,
			// /api/runs, deploy, everything the SDK's Client(api_key=...)
			// exists for -- required a JWT regardless, once JWTAuth's own
			// user-count gate was satisfied.
			desc := auth.Describe(key)
			if desc == "" {
				desc = "api-key"
			}
			claims := jwt.MapClaims{
				"sub":      "apikey:" + desc,
				"username": desc,
				"role":     string(RoleAdmin),
			}
			ctx := contextWithClaims(r.Context(), &claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
