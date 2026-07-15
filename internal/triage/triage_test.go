package triage

import (
	"testing"

	"github.com/isaqueopz/security-events-pipeline/internal/model"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name         string
		event        model.SecurityEvent
		wantCategory string
		wantScore    int
	}{
		{
			name: "sql injection SAST high",
			event: model.SecurityEvent{
				Tool: model.ToolSAST, RuleID: "go-sql-injection",
				Title: "Possível SQL Injection", Severity: model.SeverityHigh,
			},
			wantCategory: "A05:2025 - Injection",
			wantScore:    70,
		},
		{
			// SSRF não é mais categoria própria no Top 10 de 2025: foi
			// absorvido por A01 - Broken Access Control.
			name: "ssrf DAST critical",
			event: model.SecurityEvent{
				Tool: model.ToolDAST, RuleID: "ssrf-detected",
				Title: "SSRF em endpoint de callback", Severity: model.SeverityCritical,
			},
			wantCategory: "A01:2025 - Broken Access Control",
			wantScore:    100,
		},
		{
			// Componente desatualizado agora cai na nova A03 - Software
			// Supply Chain Failures.
			name: "vulnerable dependency SCA medium",
			event: model.SecurityEvent{
				Tool: model.ToolSCA, RuleID: "CVE-2024-1234",
				Title: "Dependência vulnerável detectada", Severity: model.SeverityMedium,
			},
			wantCategory: "A03:2025 - Software Supply Chain Failures",
			wantScore:    45,
		},
		{
			// Categoria nova em 2025.
			name: "unhandled exception DAST low",
			event: model.SecurityEvent{
				Tool: model.ToolDAST, RuleID: "verbose-error-handling",
				Title: "Stack trace exposto em resposta de erro", Severity: model.SeverityLow,
			},
			wantCategory: "A10:2025 - Mishandling of Exceptional Conditions",
			wantScore:    25,
		},
		{
			// "authorization" contém "auth": a precedência de A01 sobre A07
			// precisa ser preservada.
			name: "authorization bypass tem precedencia sobre auth",
			event: model.SecurityEvent{
				Tool: model.ToolSAST, RuleID: "authorization-bypass",
				Title: "Falha de authorization em endpoint interno", Severity: model.SeverityHigh,
			},
			wantCategory: "A01:2025 - Broken Access Control",
			wantScore:    70,
		},
		{
			name: "unclassified low",
			event: model.SecurityEvent{
				Tool: model.ToolSAST, RuleID: "generic-rule",
				Title: "Achado genérico", Severity: model.SeverityLow,
			},
			wantCategory: "Unclassified",
			wantScore:    20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCategory, gotScore := Classify(tt.event)
			if gotCategory != tt.wantCategory {
				t.Errorf("categoria = %q, quero %q", gotCategory, tt.wantCategory)
			}
			if gotScore != tt.wantScore {
				t.Errorf("score = %d, quero %d", gotScore, tt.wantScore)
			}
		})
	}
}
