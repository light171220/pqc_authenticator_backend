package business

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"pqc-authenticator/internal/utils"
)

type Webhook struct {
	db     *sql.DB
	logger utils.Logger
	config *utils.Config
}

func NewWebhook(db *sql.DB, logger utils.Logger, config *utils.Config) *Webhook {
	return &Webhook{
		db:     db,
		logger: logger,
		config: config,
	}
}

type WebhookPayload struct {
	Event     string                 `json:"event"`
	Timestamp int64                  `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

func (w *Webhook) Configure(businessID, webhookURL string, events []string) error {
	query := `UPDATE businesses SET webhook_url = ? WHERE id = ?`
	_, err := w.db.Exec(query, webhookURL, businessID)
	if err != nil {
		return fmt.Errorf("failed to configure webhook: %w", err)
	}

	w.logger.Info("Webhook configured", "business_id", businessID, "webhook_url", webhookURL, "events", events)
	return nil
}

func (w *Webhook) SendEvent(businessID, event string, data map[string]interface{}) error {
	business, err := w.getBusinessWebhookURL(businessID)
	if err != nil {
		return err
	}

	if business == "" {
		return nil
	}

	payload := WebhookPayload{
		Event:     event,
		Timestamp: time.Now().Unix(),
		Data:      data,
	}

	return w.sendWebhook(business, payload)
}

func (w *Webhook) sendWebhook(webhookURL string, payload WebhookPayload) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	client := &http.Client{
		Timeout: w.config.Business.WebhookTimeout,
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "PQC-Authenticator-Webhook/1.0")

	resp, err := client.Do(req)
	if err != nil {
		w.logger.Error("Failed to send webhook", "webhook_url", webhookURL, "error", err)
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		w.logger.Warn("Webhook returned non-success status", "webhook_url", webhookURL, "status", resp.StatusCode)
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	w.logger.Info("Webhook sent successfully", "webhook_url", webhookURL, "event", payload.Event)
	return nil
}

func (w *Webhook) getBusinessWebhookURL(businessID string) (string, error) {
	query := `SELECT webhook_url FROM businesses WHERE id = ?`
	var webhookURL sql.NullString
	err := w.db.QueryRow(query, businessID).Scan(&webhookURL)
	if err != nil {
		return "", err
	}
	return webhookURL.String, nil
}