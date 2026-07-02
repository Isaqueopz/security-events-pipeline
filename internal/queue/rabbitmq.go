// Package queue encapsula a comunicação com o RabbitMQ, isolando o
// restante da aplicação dos detalhes do protocolo AMQP.
package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

const QueueName = "security_events"

// Client mantém a conexão e o canal AMQP abertos durante o ciclo de vida
// do serviço (produtor ou consumidor).
type Client struct {
	conn *amqp.Connection
	ch   *amqp.Channel
}

// Connect abre a conexão com o RabbitMQ e declara a fila usada pela
// pipeline. A fila é durável para que mensagens não sejam perdidas em caso
// de restart do broker.
func Connect(amqpURL string) (*Client, error) {
	conn, err := amqp.Dial(amqpURL)
	if err != nil {
		return nil, fmt.Errorf("conectar ao rabbitmq: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("abrir canal amqp: %w", err)
	}

	if _, err := ch.QueueDeclare(
		QueueName,
		true,  // durable
		false, // auto-delete
		false, // exclusive
		false, // no-wait
		nil,
	); err != nil {
		ch.Close()
		conn.Close()
		return nil, fmt.Errorf("declarar fila %q: %w", QueueName, err)
	}

	// Garante que o consumidor processe uma mensagem por vez antes de pedir
	// a próxima, evitando que um worker fique sobrecarregado.
	if err := ch.Qos(1, 0, false); err != nil {
		ch.Close()
		conn.Close()
		return nil, fmt.Errorf("configurar qos: %w", err)
	}

	return &Client{conn: conn, ch: ch}, nil
}

func (c *Client) Close() error {
	if err := c.ch.Close(); err != nil {
		return err
	}
	return c.conn.Close()
}

// Publish serializa o payload em JSON e publica na fila de eventos de
// segurança, marcando a mensagem como persistente.
func (c *Client) Publish(ctx context.Context, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("serializar payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return c.ch.PublishWithContext(ctx,
		"",        // exchange padrão
		QueueName, // routing key = nome da fila
		false,     // mandatory
		false,     // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent,
			Body:         body,
		},
	)
}

// Consume devolve o canal de entregas da fila de eventos de segurança.
// O chamador é responsável por dar Ack/Nack em cada mensagem processada.
func (c *Client) Consume(consumerTag string) (<-chan amqp.Delivery, error) {
	return c.ch.Consume(
		QueueName,
		consumerTag,
		false, // auto-ack: false — só confirmamos após persistir com sucesso
		false, // exclusive
		false, // no-local
		false, // no-wait
		nil,
	)
}
