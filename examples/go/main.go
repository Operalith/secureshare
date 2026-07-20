package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type createResponse struct {
	URL string `json:"url"`
}

func main() {
	baseURL := strings.TrimRight(env("SECURESHARE_BASE_URL", "http://localhost:8080"), "/")
	clientID := os.Getenv("SECURESHARE_CLIENT_ID")
	clientSecret := os.Getenv("SECURESHARE_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		fmt.Fprintln(os.Stderr, "SECURESHARE_CLIENT_ID and SECURESHARE_CLIENT_SECRET are required")
		os.Exit(2)
	}

	payload := map[string]any{
		"title":              "Example login",
		"expires_in_seconds": 3600,
		"payload": map[string]any{
			"type": "structured",
			"fields": []map[string]any{
				{"name": "username", "label": "Username", "value": "example-user", "sensitive": false, "multiline": false},
				{"name": "password", "label": "Password", "value": "example-password", "sensitive": true, "multiline": false},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/secret-links", bytes.NewReader(body))
	if err != nil {
		fatal(err)
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		fatal(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "SecureShare returned HTTP %d\n", resp.StatusCode)
		os.Exit(1)
	}
	var out createResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		fatal(err)
	}
	fmt.Println(out.URL)
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
