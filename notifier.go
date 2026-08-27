package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

type Notifier struct {
	webhookURL string
	client *http.Client
	logFile *os.File

	mu sync.Mutex
	lastSent map[string]int64
	cooldown int64
}

func NewNotifier(webhookURL, logPath string, cooldownS int64) (*Notifier, error) {
	n := &Notifier{
		webhookURL: webhookURL,
		client: &http.Client{Timeout: 5 * time.Second},
		lastSent: make(map[string]int64),
		cooldown: cooldownS,
	}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		n.logFile = f
	}
	return n, nil
}

type alertEnvelope struct {
	Timestamp string  `json:"timestamp"`
	Hostname string  `json:"hostname"`
	Anomaly Anomaly `json:"anomaly"`
}

func (n *Notifier) Send(a Anomaly) bool {
	key := a.Rule + "|" + a.SrcIP
	now := time.Now().Unix()

	n.mu.Lock()
	last, ok := n.lastSent[key]
	if ok && now-last < n.cooldown {
		n.mu.Unlock()
		return false
	}
	n.lastSent[key] = now
	n.mu.Unlock()

	ts := time.Now().Format(time.RFC3339)
	env := alertEnvelope{Timestamp: ts, Hostname: hostname, Anomaly: a}

	if n.logFile != nil {
		line, _ := json.Marshal(env)
		n.logFile.Write(append(line, '\n'))
	}

	if n.webhookURL != "" {
		go n.postWebhook(env)
	}
	return true
}

func (n *Notifier) postWebhook(env alertEnvelope) {
	body, _ := json.Marshal(env)
	resp, err := n.client.Post(n.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[notifier] webhook error: %v\n", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "[notifier] webhook returned %s\n", resp.Status)
	}
}

func (n *Notifier) Close() {
	if n.logFile != nil {
		n.logFile.Close()
	}
}
