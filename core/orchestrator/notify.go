package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// WebhookNotifier delivers alert notifications to Slack and/or Telegram.
// All sends are non-blocking (goroutine). A nil notifier is a no-op.
type WebhookNotifier struct {
	slackURL       string
	telegramToken  string
	telegramChatID string
	client         *http.Client
}

// NewWebhookNotifier builds a notifier from explicit credential strings.
// Empty strings disable the corresponding channel.
func NewWebhookNotifier(slackURL, telegramToken, telegramChatID string) *WebhookNotifier {
	return &WebhookNotifier{
		slackURL:       slackURL,
		telegramToken:  telegramToken,
		telegramChatID: telegramChatID,
		client:         &http.Client{Timeout: 6 * time.Second},
	}
}

// NotifyIfNeeded sends a notification for critical and high severity events.
// All HTTP calls run in background goroutines.
func (n *WebhookNotifier) NotifyIfNeeded(event SecurityEvent) {
	if event.Severity != SeverityCritical && event.Severity != SeverityHigh {
		return
	}

	sev := strings.ToUpper(string(event.Severity))
	var mitreNote string
	if event.MITRE != nil && event.MITRE.TechniqueID != "" {
		mitreNote = fmt.Sprintf("\nMITRE: %s %s", event.MITRE.TechniqueID, event.MITRE.TechniqueName)
	}
	msg := fmt.Sprintf(
		"🚨 *Cybersecurity-AEGIS Alert*\n*Severity:* %s\n*Title:* %s\n*Source:* %s | *Category:* %s\n*Time:* %s%s",
		sev,
		event.Title,
		event.Source,
		event.Category,
		event.Timestamp.Format("2006-01-02 15:04:05 UTC"),
		mitreNote,
	)

	if n.slackURL != "" {
		go n.sendSlack(msg)
	}
	if n.telegramToken != "" && n.telegramChatID != "" {
		go n.sendTelegram(msg)
	}
}

func (n *WebhookNotifier) sendSlack(msg string) {
	payload := map[string]string{"text": msg}
	data, _ := json.Marshal(payload)
	resp, err := n.client.Post(n.slackURL, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("slack notify error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("slack notify HTTP %d", resp.StatusCode)
	}
}

func (n *WebhookNotifier) sendTelegram(msg string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.telegramToken)
	payload := map[string]any{
		"chat_id":    n.telegramChatID,
		"text":       msg,
		"parse_mode": "Markdown",
	}
	data, _ := json.Marshal(payload)
	resp, err := n.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("telegram notify error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("telegram notify HTTP %d", resp.StatusCode)
	}
}
