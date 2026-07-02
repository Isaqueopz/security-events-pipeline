// Package triage implementa a lógica de classificação automática dos
// achados: mapeamento para uma categoria OWASP e cálculo de um score de
// risco simples, usados para priorizar a remediação junto às squads.
package triage

import (
	"strings"

	"github.com/isaqueopz/security-events-pipeline/internal/model"
)

// keywordCategory associa palavras-chave encontradas no rule_id/título do
// achado a uma categoria do OWASP Top 10 (2021). É uma heurística simples,
// não um substituto para uma triagem manual completa.
var keywordCategory = []struct {
	keywords []string
	category string
}{
	{[]string{"idor", "access control", "authorization", "privilege"}, "A01:2021 - Broken Access Control"},
	{[]string{"crypto", "encryption", "hash", "cipher", "tls"}, "A02:2021 - Cryptographic Failures"},
	{[]string{"sql", "injection", "xss", "command injection", "ldap"}, "A03:2021 - Injection"},
	{[]string{"insecure design", "threat model"}, "A04:2021 - Insecure Design"},
	{[]string{"misconfig", "config", "default credentials", "cors"}, "A05:2021 - Security Misconfiguration"},
	{[]string{"outdated", "dependency", "cve", "component", "vulnerable library"}, "A06:2021 - Vulnerable and Outdated Components"},
	{[]string{"auth", "session", "credential", "password", "mfa"}, "A07:2021 - Identification and Authentication Failures"},
	{[]string{"deserialization", "integrity", "supply chain"}, "A08:2021 - Software and Data Integrity Failures"},
	{[]string{"logging", "monitoring", "audit trail"}, "A09:2021 - Security Logging and Monitoring Failures"},
	{[]string{"ssrf"}, "A10:2021 - Server-Side Request Forgery"},
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
