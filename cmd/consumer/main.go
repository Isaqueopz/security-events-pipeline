// Comando consumer consome os achados brutos publicados pelo producer,
// aplica a triagem automática (classificação OWASP + score de risco),
// persiste o resultado no Postgres e expõe uma API HTTP somente leitura
// para consulta dos achados já triados.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/isaqueopz/security-events-pipeline/internal/middleware"
	"github.com/isaqueopz/security-events-pipeline/internal/model"
	"github.com/isaqueopz/security-events-pipeline/internal/queue"
	"github.com/isaqueopz/security-events-pipeline/internal/store"
	"github.com/isaqueopz/security-events-pipeline/internal/triage"
)

// dashboardHTML é a página de visualização dos achados triados, embutida no
// binário em tempo de compilação (//go:embed) para que o container distroless
// não precise de arquivos extras em runtime.
//
//go:embed dashboard.html
var dashboardHTML []byte

func main() {
	// configura o logger global para escrever logs em JSON na saída padrão.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil))) // A09 -  Security Logging 

	// a URL de conexão (que contém credenciais) vem do ambiente, não está hardcoded no código versionado
	amqpURL := getenv("AMQP_URL", "amqp://guest:guest@localhost:5672/") // A05 - Secure Coding
	pgDSN := getenv("POSTGRES_DSN", "postgres://postgres:postgres@localhost:5432/security_events?sslmode=disable")
	addr := getenv("CONSUMER_ADDR", ":8081")

	db, err := connectStoreWithRetry(pgDSN, 10, 2*time.Second)
	if err != nil {
		slog.Error("falha ao conectar ao postgres", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := db.Migrate(ctx); err != nil {
		slog.Error("falha ao aplicar migração", "error", err)
		os.Exit(1)
	}

	q, err := connectQueueWithRetry(amqpURL, 10, 2*time.Second)
	if err != nil {
		//  padrão universal de Go: (resultado, erro).
		slog.Error("falha ao conectar ao rabbitmq", "error", err)
		// — o tratamento de erro idiomático de Go.
		os.Exit(1)
	}
	// defer garante limpeza; roda em ordem LIFO no fim da função
	defer q.Close()

	go consumeLoop(ctx, q, db)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", handleDashboard)
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /triaged-events", handleList(db))
	mux.HandleFunc("GET /triaged-events/{id}", handleGetByID(db))

	handler := middleware.Logging(mux)
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("consumer ouvindo", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("erro no servidor http", "error", err)
			os.Exit(1)
		}
	}()

	waitForShutdown(srv, cancel)
}

// consumeLoop lê as mensagens da fila, aplica a triagem e persiste o
// resultado. Mensagens malformadas são descartadas (sem requeue) para não
// travar a fila; falhas de persistência são recolocadas na fila para
// nova tentativa.
func consumeLoop(ctx context.Context, q *queue.Client, db *store.Store) {
	deliveries, err := q.Consume("consumer-1")
	if err != nil {
		slog.Error("falha ao registrar consumidor", "error", err)
		os.Exit(1)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case d, ok := <-deliveries:
			if !ok {
				return
			}

			var evt model.SecurityEvent
			if err := json.Unmarshal(d.Body, &evt); err != nil {
				slog.Error("mensagem malformada descartada", "error", err)
				d.Nack(false, false)
				continue
			}

			owaspCategory, riskScore := triage.Classify(evt)
			triaged := model.TriagedEvent{
				SecurityEvent: evt,
				OWASPCategory: owaspCategory,
				RiskScore:     riskScore,
				Status:        "open",
				ProcessedAt:   time.Now().UTC(),
			}

			insertCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := db.Insert(insertCtx, triaged)
			cancel()

			if err != nil {
				slog.Error("falha ao persistir evento triado, reencaminhando", "id", evt.ID, "error", err)
				d.Nack(false, true)
				continue
			}

			slog.Info("evento triado", "id", evt.ID, "owasp_category", owaspCategory, "risk_score", riskScore)
			d.Ack(false)
		}
	}
}

func connectQueueWithRetry(url string, attempts int, delay time.Duration) (*queue.Client, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		q, err := queue.Connect(url)
		if err == nil {
			return q, nil
		}
		lastErr = err
		slog.Warn("rabbitmq indisponível, tentando novamente", "tentativa", i+1, "error", err)
		time.Sleep(delay)
	}
	return nil, lastErr
}

func connectStoreWithRetry(dsn string, attempts int, delay time.Duration) (*store.Store, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		db, err := store.Open(dsn)
		if err == nil {
			return db, nil
		}
		lastErr = err
		slog.Warn("postgres indisponível, tentando novamente", "tentativa", i+1, "error", err)
		time.Sleep(delay)
	}
	return nil, lastErr
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// handleDashboard serve a página HTML de visualização dos achados triados.
// A página consome a própria API GET /triaged-events (mesma origem, sem CORS).
func handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(dashboardHTML)
}

func handleList(db *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := 50
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 200 {
				limit = n
			}
		}

		events, err := db.List(r.Context(), limit)
		if err != nil {
			slog.Error("falha ao listar eventos", "error", err)
			http.Error(w, `{"error":"erro interno"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}
}

func handleGetByID(db *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		event, err := db.GetByID(r.Context(), id)
		if err != nil {
			http.Error(w, `{"error":"evento não encontrado"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(event)
	}
}

func waitForShutdown(srv *http.Server, cancelConsumer context.CancelFunc) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	slog.Info("encerrando consumer...")
	cancelConsumer()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("erro ao encerrar servidor", "error", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
