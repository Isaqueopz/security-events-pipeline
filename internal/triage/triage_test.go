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
			wantCategory: "A03:2021 - Injection",
			wantScore:    70,
		},
		{
			name: "ssrf DAST critical",
			event: model.SecurityEvent{
				Tool: model.ToolDAST, RuleID: "ssrf-detected",
				Title: "SSRF em endpoint de callback", Severity: model.SeverityCritical,
			},
			wantCategory: "A10:2021 - Server-Side Request Forgery",
			wantScore:    100,
		},
		{
			name: "vulnerable dependency SCA medium",
			event: model.SecurityEvent{
				Tool: model.ToolSCA, RuleID: "CVE-2024-1234",
				Title: "Dependência vulnerável detectada", Severity: model.SeverityMedium,
			},
			wantCategory: "A06:2021 - Vulnerable and Outdated Components",
			wantScore:    45,
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
