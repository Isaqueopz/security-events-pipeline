// Package triage implementa a lógica de classificação automática dos
// achados: mapeamento para uma categoria OWASP e cálculo de um score de
// risco simples, usados para priorizar a remediação junto às squads.
package triage

import (
	"strings"

	"github.com/isaqueopz/security-events-pipeline/internal/model"
)

// keywordCategory associa palavras-chave encontradas no rule_id/título do
// achado a uma categoria do OWASP Top 10 (2025). É uma heurística simples,
// não um substituto para uma triagem manual completa.
//
// A ordem das entradas define a precedência: Classify para na primeira
// categoria que casar. Isso importa porque as palavras-chave se sobrepõem —
// "authorization" contém "auth", então A01 precisa ser avaliada antes de A07
// para que um achado de autorização não caia em falhas de autenticação.
//
// Mudanças relevantes em relação ao Top 10 de 2021:
//   - SSRF deixou de ser categoria própria (era A10:2021) e foi absorvido
//     por A01:2025 - Broken Access Control.
//   - "Vulnerable and Outdated Components" (A06:2021) foi absorvida pela nova
//     A03:2025 - Software Supply Chain Failures, que também recebeu o tema de
//     supply chain antes mapeado em A08:2021.
//   - A10:2025 - Mishandling of Exceptional Conditions é uma categoria nova.
var keywordCategory = []struct {
	keywords []string
	category string
}{
	{[]string{"idor", "access control", "authorization", "privilege", "ssrf"}, "A01:2025 - Broken Access Control"},
	{[]string{"misconfig", "config", "default credentials", "cors"}, "A02:2025 - Security Misconfiguration"},
	{[]string{"supply chain", "outdated", "dependency", "cve", "component", "vulnerable library"}, "A03:2025 - Software Supply Chain Failures"},
	{[]string{"crypto", "encryption", "hash", "cipher", "tls"}, "A04:2025 - Cryptographic Failures"},
	{[]string{"sql", "injection", "xss", "command injection", "ldap"}, "A05:2025 - Injection"},
	{[]string{"insecure design", "threat model"}, "A06:2025 - Insecure Design"},
	{[]string{"auth", "session", "credential", "password", "mfa"}, "A07:2025 - Authentication Failures"},
	{[]string{"deserialization", "integrity"}, "A08:2025 - Software or Data Integrity Failures"},
	{[]string{"logging", "monitoring", "alerting", "audit trail"}, "A09:2025 - Security Logging and Alerting Failures"},
	{[]string{"exceptional condition", "error handling", "fail open", "unhandled exception", "stack trace"}, "A10:2025 - Mishandling of Exceptional Conditions"},
}

// severityWeight define o peso base de cada severidade no cálculo do score
// de risco (0-100).
var severityWeight = map[model.Severity]int{
	model.SeverityInfo:     5,
	model.SeverityLow:      20,
	model.SeverityMedium:   45,
	model.SeverityHigh:     70,
	model.SeverityCritical: 95,
}

// toolBonus reflete que achados de DAST (explorados em runtime) tendem a
// indicar um risco mais imediato do que achados estáticos de SAST/SCA.
var toolBonus = map[model.ToolType]int{
	model.ToolSAST: 0,
	model.ToolSCA:  0,
	model.ToolDAST: 5,
}

// Classify recebe um evento validado e devolve a categoria OWASP sugerida
// e um score de risco (0-100) usados para priorizar a remediação.
func Classify(e model.SecurityEvent) (owaspCategory string, riskScore int) {
	haystack := strings.ToLower(e.RuleID + " " + e.Title + " " + e.Description)

	owaspCategory = "Unclassified"
	for _, entry := range keywordCategory {
		for _, kw := range entry.keywords {
			if strings.Contains(haystack, kw) {
				owaspCategory = entry.category
				break
			}
		}
		if owaspCategory != "Unclassified" {
			break
		}
	}

	riskScore = severityWeight[model.Severity(strings.ToLower(string(e.Severity)))] + toolBonus[model.ToolType(strings.ToUpper(string(e.Tool)))]
	if riskScore > 100 {
		riskScore = 100
	}
	return owaspCategory, riskScore
}
