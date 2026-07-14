// Package middleware fornece proteções básicas para os endpoints HTTP
// expostos pelo produtor e pelo consumidor.
package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// maxBodyBytes limita o tamanho do corpo das requisições para mitigar
// ataques de negação de serviço via payloads gigantes.
const maxBodyBytes = 1 << 20 // 1 MiB

// Logging registra método, caminho, status e duração de cada requisição.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		// evitando OWASP A09 (Falhas de Logging e Monitoramento).
		slog.Info("http_request", 
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// LimitBody restringe o tamanho máximo do corpo da requisição.
func LimitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// RateLimiter implementa um limitador simples de token bucket por IP de
// origem, para reduzir o risco de abuso/DoS nos endpoints públicos.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     int           // tokens repostos por intervalo
	interval time.Duration // intervalo de reposição
	capacity int           // tamanho máximo do bucket
}

type bucket struct {
	tokens   int
	lastFill time.Time
}

func NewRateLimiter(rate int, interval time.Duration, capacity int) *RateLimiter {
	return &RateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     rate,
		interval: interval,
		capacity: capacity,
	}
}

func (rl *RateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: rl.capacity - 1, lastFill: time.Now()}
		rl.buckets[key] = b
		return true
	}

	elapsed := time.Since(b.lastFill)
	refill := int(elapsed/rl.interval) * rl.rate
	if refill > 0 {
		b.tokens = min(rl.capacity, b.tokens+refill)
		b.lastFill = time.Now()
	}

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// Middleware aplica o rate limit por IP remoto, respondendo 429 quando o
// limite é excedido.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(clientIP(r)) {
			http.Error(w, `{"error":"rate limit excedido, tente novamente mais tarde"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP extrai apenas o endereço IP de r.RemoteAddr, descartando a porta
// de origem. Isso é essencial para o rate limit: r.RemoteAddr tem o formato
// "IP:porta", e a porta muda a cada nova conexão TCP — se a usássemos como
// chave, cada conexão viraria um "cliente" novo e o limite nunca valeria.
// Nota: atrás de um proxy/load balancer, RemoteAddr seria o IP do proxy;
// nesse caso o correto seria ler X-Forwarded-For, mas apenas confiando no
// proxy (o header é forjável pelo cliente).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
