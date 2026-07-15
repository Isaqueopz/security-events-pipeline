# security-events-pipeline

Pipeline assíncrona em Go para triagem de achados de segurança (SAST, SCA e DAST), simulando um fluxo real de AppSec: uma ferramenta de scanner (Semgrep, Trivy, OWASP ZAP, etc.) reporta um achado bruto, o achado é enfileirado, e um worker separado consome, classifica e persiste o resultado para acompanhamento pelas squads.

```
POST /events                RabbitMQ                 Postgres
(producer) ───────────► [security_events] ───────► (consumer) ───► triaged_events
                                                          │
                                                          └──► GET /triaged-events (consumer)
```

## Motivação

Projeto de estudo/portfólio para praticar Go aplicado a cenários de AppSec: mensageria (produtor/consumidor), persistência com queries parametrizadas, e boas práticas de secure coding (validação de entrada, rate limiting, timeouts, logging estruturado, sem segredos hardcoded).

## Stack

- Go 1.25, apenas `net/http` (stdlib) para os servidores HTTP
- [RabbitMQ](https://www.rabbitmq.com/) (`amqp091-go`) como broker de mensageria
- PostgreSQL (`jackc/pgx`) para persistência dos achados triados
- Docker Compose para orquestração local

## Como rodar

```bash
cp .env.example .env
docker compose up --build
```

Serviços expostos:

- Producer: `http://localhost:8080`
- Consumer (API de leitura): `http://localhost:8081`
- RabbitMQ management UI: `http://localhost:15672` (guest/guest)

## Exemplo de uso

Publicar um achado (simulando a saída de um scanner SAST):

```bash
curl -X POST http://localhost:8080/events \
  -H "Content-Type: application/json" \
  -d '{
    "source": "semgrep",
    "tool": "SAST",
    "rule_id": "go-sql-injection",
    "title": "Possível SQL Injection via concatenação de string",
    "description": "Query construída com fmt.Sprintf usando input do usuário",
    "file_path": "internal/handlers/user.go",
    "repo_name": "backend-orders",
    "severity": "high"
  }'
```

Resposta:

```json
{"id": "b1f2...", "status": "queued"}
```

Consultar os achados já triados pelo consumer:

```bash
curl http://localhost:8081/triaged-events
curl http://localhost:8081/triaged-events/b1f2...
```

O consumer classifica automaticamente o achado em uma categoria do OWASP Top 10 (2025) com base em palavras-chave do `rule_id`/`title`/`description`, e calcula um `risk_score` (0-100) combinando severidade e tipo de ferramenta.

## Decisões de secure coding

- **Sem SQL injection**: todas as queries usam parâmetros posicionais (`$1, $2, ...`) via `database/sql`, nunca concatenação de strings (`internal/store/postgres.go`).
- **Validação na borda**: o producer valida e sanitiza os campos do evento antes de publicar na fila (`internal/model/event.go`), evitando que dados malformados cheguem ao consumer.
- **Rate limiting**: o endpoint `POST /events` tem um limitador de taxa por IP (token bucket) para reduzir o risco de abuso/DoS (`internal/middleware`).
- **Limite de tamanho de payload**: requisições maiores que 1 MiB são rejeitadas antes do parse do JSON.
- **Sem segredos no código**: strings de conexão e credenciais vêm de variáveis de ambiente (`.env`, nunca commitado — ver `.gitignore`).
- **Idempotência**: o `INSERT` no Postgres usa `ON CONFLICT DO NOTHING`, então um redelivery do RabbitMQ (após falha e novo Nack) não duplica dados.
- **Ack manual**: mensagens só são confirmadas (`Ack`) após persistência bem-sucedida; falhas de banco recolocam a mensagem na fila (`Nack` com requeue).
- **Containers non-root**: as imagens finais usam `distroless:nonroot`, sem shell e sem usuário root.

## Estrutura

```
cmd/producer/     API HTTP que recebe e valida achados, publica no RabbitMQ
cmd/consumer/     Worker que consome da fila, triagem + persistência, API de leitura
internal/model/   Structs e validação dos eventos
internal/triage/  Classificação OWASP + cálculo de risk score
internal/queue/   Cliente RabbitMQ (publish/consume)
internal/store/   Acesso ao Postgres (queries parametrizadas)
internal/middleware/ Logging, rate limit e limite de tamanho de request
```

## Rodando sem Docker

```bash
# terminal 1: suba apenas rabbitmq e postgres
docker compose up rabbitmq postgres

# terminal 2
go run ./cmd/producer

# terminal 3
go run ./cmd/consumer
```
