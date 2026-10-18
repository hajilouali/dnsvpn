// Package admin is the web management panel: a small REST API over the user store
// plus an embedded single-page UI, protected by HTTP basic auth. It lets the operator
// create users, set quota/expiry/concurrency limits, enable/disable and delete them,
// and view usage.
package admin

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"dnsvpn/internal/configlink"
	"dnsvpn/server/store"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

const adminPassKey = "admin_pass_hash"

//go:embed web/*
var webFS embed.FS

// Panel serves the admin UI/API.
type Panel struct {
	store      *store.Store
	adminUser  string
	zone       string // tunnel zone, baked into each user's config link
	psk        string // shared key, baked into each user's config link
	candidates string // default resolver candidates offered to clients
}

// New builds a Panel handler. adminPass is the bootstrap password: it is used only to
// seed the stored bcrypt hash on first run; afterwards the hash in the database wins, so
// a password changed in the panel survives restarts (and the installer's flag no longer
// overrides it). zone/psk/candidates are embedded into the per-user config links.
func New(st *store.Store, adminUser, adminPass, zone, psk, candidates string) (*Panel, error) {
	p := &Panel{
		store: st, adminUser: adminUser,
		zone: zone, psk: psk, candidates: candidates,
	}
	if _, ok, err := st.GetSetting(adminPassKey); err != nil {
		return nil, err
	} else if !ok {
		if err := p.setPassword(adminPass); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// setPassword stores a bcrypt hash of pw as the admin password.
func (p *Panel) setPassword(pw string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return p.store.SetSetting(adminPassKey, string(h))
}

// link builds the self-contained dnsvpn:// config link for a user.
func (p *Panel) link(u *store.User) string {
	return configlink.Encode(configlink.Config{
		Name:       u.Username,
		Zone:       p.zone,
		PSK:        p.psk,
		Token:      u.Token,
		Candidates: p.candidates,
	})
}

// Handler returns the http.Handler for the panel (mount under "/").
func (p *Panel) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/users", p.auth(p.listUsers))
	mux.HandleFunc("POST /api/users", p.auth(p.createUser))
	mux.HandleFunc("PUT /api/users/{id}", p.auth(p.updateUser))
	mux.HandleFunc("POST /api/users/{id}/enable", p.auth(p.enableUser(true)))
	mux.HandleFunc("POST /api/users/{id}/disable", p.auth(p.enableUser(false)))
	mux.HandleFunc("POST /api/users/{id}/reset", p.auth(p.resetUser))
	mux.HandleFunc("GET /api/users/{id}/qr", p.auth(p.userQR))
	mux.HandleFunc("DELETE /api/users/{id}", p.auth(p.deleteUser))
	mux.HandleFunc("POST /api/password", p.auth(p.changePassword))

	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", p.authPage(http.FileServer(http.FS(sub))))
	return mux
}

// --- auth --------------------------------------------------------------------

func (p *Panel) checkAuth(r *http.Request) bool {
	u, pw, ok := r.BasicAuth()
	if !ok {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(u), []byte(p.adminUser)) != 1 {
		return false
	}
	hash, ok2, err := p.store.GetSetting(adminPassKey)
	if err != nil || !ok2 {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func (p *Panel) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.checkAuth(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="dnsvpn"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func (p *Panel) authPage(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.checkAuth(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="dnsvpn"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}
}

// --- api ---------------------------------------------------------------------

type userView struct {
	ID            int64  `json:"id"`
	Username      string `json:"username"`
	Token         string `json:"token"`
	Enabled       bool   `json:"enabled"`
	ExpiresAt     int64  `json:"expires_at"` // unix sec, 0 = never
	QuotaBytes    int64  `json:"quota_bytes"`
	UsedBytes     int64  `json:"used_bytes"`
	MaxConcurrent int    `json:"max_concurrent"`
	Active        int    `json:"active"`
	CreatedAt     int64  `json:"created_at"`
	Link          string `json:"link"` // dnsvpn:// config link for this user
}

func (p *Panel) view(u *store.User, active int) userView {
	v := userView{
		ID: u.ID, Username: u.Username, Token: u.Token, Enabled: u.Enabled,
		QuotaBytes: u.QuotaBytes, UsedBytes: u.UsedBytes,
		MaxConcurrent: u.MaxConcurrent, Active: active, CreatedAt: u.CreatedAt.Unix(),
		Link: p.link(u),
	}
	if u.ExpiresAt != nil {
		v.ExpiresAt = u.ExpiresAt.Unix()
	}
	return v
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (p *Panel) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := p.store.ListUsers()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	out := make([]userView, 0, len(users))
	for _, u := range users {
		out = append(out, p.view(u, p.store.ActiveCount(u.Token)))
	}
	writeJSON(w, 200, out)
}

type createReq struct {
	Username      string `json:"username"`
	QuotaBytes    int64  `json:"quota_bytes"`
	MaxConcurrent int    `json:"max_concurrent"`
	ExpiresInDays int    `json:"expires_in_days"` // 0 = never
}

func (p *Panel) createUser(w http.ResponseWriter, r *http.Request) {
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	var exp *time.Time
	if req.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresInDays)
		exp = &t
	}
	u, err := p.store.CreateUser(req.Username, "", req.QuotaBytes, req.MaxConcurrent, exp)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, 201, p.view(u, 0))
}

type updateReq struct {
	QuotaBytes    int64 `json:"quota_bytes"`
	MaxConcurrent int   `json:"max_concurrent"`
	ExpiresInDays int   `json:"expires_in_days"` // 0 = never, -1 = leave as never
}

func idParam(r *http.Request) (int64, error) { return strconv.ParseInt(r.PathValue("id"), 10, 64) }

func (p *Panel) updateUser(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	var req updateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	var exp *time.Time
	if req.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresInDays)
		exp = &t
	}
	if err := p.store.UpdateLimits(id, req.QuotaBytes, req.MaxConcurrent, exp); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	u, _ := p.store.GetUser(id)
	writeJSON(w, 200, p.view(u, p.store.ActiveCount(u.Token)))
}

func (p *Panel) enableUser(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := idParam(r)
		if err != nil {
			http.Error(w, "bad id", 400)
			return
		}
		if err := p.store.SetEnabled(id, enabled); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, map[string]bool{"enabled": enabled})
	}
}

func (p *Panel) resetUser(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	if err := p.store.ResetUsage(id); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

type passwordReq struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// changePassword verifies the current admin password and stores a new bcrypt hash.
func (p *Panel) changePassword(w http.ResponseWriter, r *http.Request) {
	var req passwordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if len(req.New) < 6 {
		http.Error(w, "new password must be at least 6 characters", 400)
		return
	}
	hash, ok, err := p.store.GetSetting(adminPassKey)
	if err != nil || !ok {
		http.Error(w, "server error", 500)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Old)) != nil {
		http.Error(w, "current password is wrong", 403)
		return
	}
	if err := p.setPassword(req.New); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// userQR returns a PNG QR code of the user's dnsvpn:// config link, so it can be
// scanned straight into the Android app.
func (p *Panel) userQR(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	u, err := p.store.GetUser(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	png, err := qrcode.Encode(p.link(u), qrcode.Medium, 320)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

func (p *Panel) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	if err := p.store.DeleteUser(id); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}
