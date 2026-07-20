package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"secureshare/internal/config"
)

type contextKey string

const RequestIDKey contextKey = "request_id"

func RequestID(ctx context.Context) string {
	if value, ok := ctx.Value(RequestIDKey).(string); ok {
		return value
	}
	return ""
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func SecurityHeaders(cfg config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store, private, max-age=0")
		h.Set("Pragma", "no-cache")
		h.Set("Expires", "0")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if cfg.EnableHSTS {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func Logging(logger *slog.Logger, cfg config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		start := time.Now()
		ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
		next.ServeHTTP(rec, r.WithContext(ctx))
		logger.Info("http_request",
			"request_id", requestID,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"latency_ms", time.Since(start).Milliseconds(),
			"ip_hash", IPHash(cfg.RequestIPHashPepper, r),
		)
	})
}

func IPHash(pepper string, r *http.Request) string {
	ip := clientIP(r)
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(ip))
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		first := strings.TrimSpace(strings.Split(forwarded, ",")[0])
		if first != "" {
			host = first
		}
	}
	return host
}

func newRequestID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(buf)
}
