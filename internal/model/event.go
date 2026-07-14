// Package model define as estruturas de dados compartilhadas entre o
// produtor e o consumidor da pipeline de eventos de segurança.
package model

import (
	"errors"
	"strings"
	"time"
)

// Severity é a severidade bruta reportada pela ferramenta de origem
// (SAST, SCA ou DAST).
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) valid() bool {
	switch Severity(strings.ToLower(string(s))) {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// ToolType identifica a categoria da ferramenta que originou o achado.
type ToolType string

const (
	ToolSAST ToolType = "SAST"
	ToolSCA  ToolType = "SCA"
	ToolDAST ToolType = "DAST"
)

func (t ToolType) valid() bool {
	switch ToolType(strings.ToUpper(string(t))) {
	case ToolSAST, ToolSCA, ToolDAST:
		return true
	default:
		return false
	}
}

// SecurityEvent representa um achado bruto reportado por uma ferramenta
// de segurança (ex: Semgrep, Trivy, OWASP ZAP) antes da triagem.
type SecurityEvent struct {
	ID          string    `json:"id"`
	Source      string    `json:"source"`  // ex: "semgrep", "trivy", "zap"
	Tool        ToolType  `json:"tool"`    // SAST | SCA | DAST
	RuleID      string    `json:"rule_id"` // ex: "CWE-89", "go-sql-injection"
	Title       string    `json:"title"`
	Description string    `json:"description"`
	FilePath    string    `json:"file_path,omitempty"`
	RepoName    string    `json:"repo_name"`
	Severity    Severity  `json:"severity"`
	CreatedAt   time.Time `json:"created_at"` // campo é preenchido pelo servidor
}

// Validate garante que os campos obrigatórios do evento foram preenchidos
// corretamente antes de ele ser publicado na fila. Validar na borda evita
// que dados malformados cheguem ao consumidor e, futuramente, ao banco.
func (e *SecurityEvent) Validate() error {
	e.Source = strings.TrimSpace(e.Source)
	e.RuleID = strings.TrimSpace(e.RuleID)
	e.Title = strings.TrimSpace(e.Title)
	e.RepoName = strings.TrimSpace(e.RepoName)

	switch {
	case e.Source == "":
		return errors.New("source é obrigatório")
	case e.RuleID == "":
		return errors.New("rule_id é obrigatório")
	case e.Title == "":
		return errors.New("title é obrigatório")
	case e.RepoName == "":
		return errors.New("repo_name é obrigatório")
	case !e.Tool.valid():
		return errors.New("tool deve ser SAST, SCA ou DAST")
	case !e.Severity.valid():
		return errors.New("severity deve ser info, low, medium, high ou critical")
	}
	return nil
}

// TriagedEvent é o resultado da triagem automática feita pelo consumidor:
// classificação OWASP, score de risco e status de acompanhamento.
type TriagedEvent struct {
	SecurityEvent
	OWASPCategory string    `json:"owasp_category"`
	RiskScore     int       `json:"risk_score"`
	Status        string    `json:"status"` // open | in_remediation | resolved
	ProcessedAt   time.Time `json:"processed_at"`
}
