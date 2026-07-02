// Comando producer expõe uma API HTTP que recebe achados brutos de
// ferramentas de segurança (SAST/SCA/DAST) e os publica na fila do
// RabbitMQ para triagem assíncrona pelo consumer.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/isaqueopz/security-events-pipeline/internal/middleware"
	"github.com/isaqueopz/security-events-pipeline/internal/model"
	"github.com/isaqueopz/security-events-pipeline/internal/queue"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	amqpURL := getenv("AMQP_URL", "amqp://guest:guest@localhost:5672/")
	addr := getenv("PRODUCER_ADDR", ":8080")

	q, err := connectWithRetry(amqpURL, 10, 2*time.Second)
	if err != nil {
		slog.Error("falha ao conectar ao rabbitmq", "error", err)
		os.Exit(1)
	}
	defer q.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("POST /events", handleCreateEvent(q))

	limiter := middleware.NewRateLimiter(20, time.Second, 40)
	handler := middleware.Logging(middleware.LimitBody(limiter.Middleware(mux)))

	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("producer ouvindo", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("erro no servidor http", "error", err)
			os.Exit(1)
		}
	}()

	waitForShutdown(srv)
}

// connectWithRetry tenta conectar ao RabbitMQ algumas vezes antes de
// desistir, já que em ambientes com docker-compose o broker pode demorar
// alguns segundos a mais para ficar pronto do que o próprio serviço Go.
func connectWithRetry(url string, attempts int, delay time.Duration) (*queue.Client, error) {
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

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func handleCreateEvent(q *queue.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var evt model.SecurityEvent
		if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
			writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
			return
		}

		if err := evt.Validate(); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}

		evt.ID = uuid.NewString()
		evt.CreatedAt = time.Now().UTC()

		if err := q.Publish(r.Context(), evt); err != nil {
			slog.Error("falha ao publicar evento", "error", err)
			writeError(w, http.StatusServiceUnavailable, "não foi possível enfileirar o evento")
			return
		}

		slog.Info("evento publicado", "id", evt.ID, "source", evt.Source, "severity", evt.Severity)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"id": evt.ID, "status": "queued"})
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func waitForShutdown(srv *http.Server) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	slog.Info("encerrando producer...")
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
