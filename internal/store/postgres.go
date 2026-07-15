// Package store cuida da persistência dos achados triados no Postgres.
// Todas as queries usam parâmetros posicionais ($1, $2, ...) — nunca
// concatenação de strings — para eliminar o risco de SQL injection
// (OWASP A05:2025 - Injection).
package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/isaqueopz/security-events-pipeline/internal/model"
)

type Store struct {
	db *sql.DB
}

func Open(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("abrir conexão com postgres: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("verificar conexão com postgres: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Migrate cria o schema necessário caso ainda não exista. Em um ambiente
// real isso seria feito por uma ferramenta de migração dedicada
// (ex: golang-migrate); aqui mantemos simples para fins de demonstração.
func (s *Store) Migrate(ctx context.Context) error {
	const schema = `
	CREATE TABLE IF NOT EXISTS triaged_events (
		id             TEXT PRIMARY KEY,
		source         TEXT NOT NULL,
		tool           TEXT NOT NULL,
		rule_id        TEXT NOT NULL,
		title          TEXT NOT NULL,
		description    TEXT NOT NULL,
		file_path      TEXT,
		repo_name      TEXT NOT NULL,
		severity       TEXT NOT NULL,
		owasp_category TEXT NOT NULL,
		risk_score     INT NOT NULL,
		status         TEXT NOT NULL DEFAULT 'open',
		created_at     TIMESTAMPTZ NOT NULL,
		processed_at   TIMESTAMPTZ NOT NULL
	);`
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

// Insert grava um achado já triado. Usa ON CONFLICT para tornar o
// processamento idempotente: reprocessar a mesma mensagem (ex: após um
// redelivery do broker) não duplica registros.
func (s *Store) Insert(ctx context.Context, e model.TriagedEvent) error {
	const query = `
	INSERT INTO triaged_events (
		id, source, tool, rule_id, title, description, file_path, repo_name,
		severity, owasp_category, risk_score, status, created_at, processed_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
	ON CONFLICT (id) DO NOTHING`

	_, err := s.db.ExecContext(ctx, query,
		e.ID, e.Source, string(e.Tool), e.RuleID, e.Title, e.Description,
		e.FilePath, e.RepoName, string(e.Severity), e.OWASPCategory,
		e.RiskScore, e.Status, e.CreatedAt, e.ProcessedAt,
	)
	return err
}

// List devolve os achados triados mais recentes, com paginação simples.
func (s *Store) List(ctx context.Context, limit int) ([]model.TriagedEvent, error) {
	const query = `
	SELECT id, source, tool, rule_id, title, description, file_path, repo_name,
	       severity, owasp_category, risk_score, status, created_at, processed_at
	FROM triaged_events
	ORDER BY processed_at DESC
	LIMIT $1`

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []model.TriagedEvent
	for rows.Next() {
		var e model.TriagedEvent
		var filePath sql.NullString
		if err := rows.Scan(
			&e.ID, &e.Source, &e.Tool, &e.RuleID, &e.Title, &e.Description,
			&filePath, &e.RepoName, &e.Severity, &e.OWASPCategory,
			&e.RiskScore, &e.Status, &e.CreatedAt, &e.ProcessedAt,
		); err != nil {
			return nil, err
		}
		e.FilePath = filePath.String
		events = append(events, e)
	}
	return events, rows.Err()
}

// GetByID busca um achado triado específico. Retorna sql.ErrNoRows se não
// existir, para que o handler HTTP traduza isso em um 404.
func (s *Store) GetByID(ctx context.Context, id string) (model.TriagedEvent, error) {
	const query = `
	SELECT id, source, tool, rule_id, title, description, file_path, repo_name,
	       severity, owasp_category, risk_score, status, created_at, processed_at
	FROM triaged_events
	WHERE id = $1`

	var e model.TriagedEvent
	var filePath sql.NullString
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&e.ID, &e.Source, &e.Tool, &e.RuleID, &e.Title, &e.Description,
		&filePath, &e.RepoName, &e.Severity, &e.OWASPCategory,
		&e.RiskScore, &e.Status, &e.CreatedAt, &e.ProcessedAt,
	)
	e.FilePath = filePath.String
	return e, err
}
