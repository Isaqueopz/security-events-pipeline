package model

import "testing"

func TestSecurityEventValidate(t *testing.T) {
	valid := func() SecurityEvent {
		return SecurityEvent{
			Source:   "semgrep",
			Tool:     ToolSAST,
			RuleID:   "go-sql-injection",
			Title:    "Possível SQL Injection",
			RepoName: "backend-orders",
			Severity: SeverityHigh,
		}
	}

	if err := func() error { e := valid(); return e.Validate() }(); err != nil {
		t.Fatalf("evento válido não deveria falhar: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*SecurityEvent)
		wantErr bool
	}{
		{"source vazio", func(e *SecurityEvent) { e.Source = "  " }, true},
		{"tool inválida", func(e *SecurityEvent) { e.Tool = "PENTEST" }, true},
		{"severity inválida", func(e *SecurityEvent) { e.Severity = "urgent" }, true},
		{"title vazio", func(e *SecurityEvent) { e.Title = "" }, true},
		{"repo vazio", func(e *SecurityEvent) { e.RepoName = "" }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := valid()
			tt.mutate(&e)
			err := e.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
