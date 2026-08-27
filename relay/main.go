package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type alertEnvelope struct {
	Timestamp string `json:"timestamp"`
	Hostname  string `json:"hostname"`
	Anomaly   struct {
		Rule  string  `json:"rule"`
		SrcIP  string  `json:"src_ip"`
		Severity string  `json:"severity"`
		Score  float64 `json:"score"`
		Detail  string  `json:"detail"`
	} `json:"anomaly"`
}

type discordPayload struct {
	Content string `json:"content"`
}

func main() {
	listenAddr := flag.String("listen", ":8080", "HTTP listen address")
	path := flag.String("path", "/webhook", "HTTP path to accept alerts on")
	discordWebhook := flag.String("discord", os.Getenv("DISCORD_WEBHOOK_URL"), "Discord webhook URL to forward to")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc(*path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var alert alertEnvelope
		if err := json.Unmarshal(body, &alert); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		msg := buildMessage(alert)
		log.Printf("relay: %s", strings.ReplaceAll(msg, "\n", " | "))

		if *discordWebhook == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		payload := discordPayload{Content: msg}
		encoded, err := json.Marshal(payload)
		if err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
			return
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(*discordWebhook, "application/json", bytes.NewReader(encoded))
		if err != nil {
			log.Printf("relay: discord post failed: %v", err)
			http.Error(w, "forward failed", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 {
			http.Error(w, fmt.Sprintf("discord returned %s", resp.Status), http.StatusBadGateway)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	log.Printf("relay: listening on %s%s", *listenAddr, *path)
	if *discordWebhook == "" {
		log.Printf("relay: DISCORD_WEBHOOK_URL not set, requests will only be logged")
	}
	if err := http.ListenAndServe(*listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}

func buildMessage(alert alertEnvelope) string {
	return fmt.Sprintf("ids alert\nrule: %s\nsource: %s\nseverity: %s\nscore: %.2f\nwhen: %s\nwhy: %s\nhost: %s",
		alert.Anomaly.Rule,
		alert.Anomaly.SrcIP,
		alert.Anomaly.Severity,
		alert.Anomaly.Score,
		alert.Timestamp,
		alert.Anomaly.Detail,
		alert.Hostname,
	)
}
