package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestSecretLifecycleIntegration(t *testing.T) {
	client := integrationClient(t)
	marker := "integration-secret-value"
	created := client.create(t, map[string]any{
		"title":               "Integration secret",
		"description":         "Created by integration test",
		"recipient_reference": "integration",
		"secret":              map[string]any{"value": marker},
		"expires_in_seconds":  900,
		"password":            nil,
		"max_failed_attempts": 5,
	})

	client.assertCiphertextOnly(t, created.ID, marker)

	prepareStatus, prepareBody := client.postJSON(t, "/api/v1/secret-links/prepare", map[string]any{"token": created.Token}, nil)
	if prepareStatus != 200 || prepareBody["may_attempt"] != true {
		t.Fatalf("prepare = %d %#v, want may_attempt true", prepareStatus, prepareBody)
	}

	status, body := client.postJSON(t, "/api/v1/secret-links/consume", map[string]any{"token": created.Token}, nil)
	if status != 200 {
		t.Fatalf("consume = %d %#v, want 200", status, body)
	}
	secret := body["secret"].(map[string]any)
	if secret["value"] != marker {
		t.Fatalf("secret value = %#v, want %q", secret["value"], marker)
	}

	status, body = client.postJSON(t, "/api/v1/secret-links/consume", map[string]any{"token": created.Token}, nil)
	if status != 410 || body["code"] != "SECRET_UNAVAILABLE" {
		t.Fatalf("second consume = %d %#v, want generic 410", status, body)
	}
}

func TestConcurrentConsumeIntegration(t *testing.T) {
	client := integrationClient(t)
	created := client.create(t, map[string]any{
		"title":              "Concurrent secret",
		"secret":             map[string]any{"value": "only-once"},
		"expires_in_seconds": 900,
	})

	const requests = 20
	var wg sync.WaitGroup
	statuses := make(chan int, requests)
	successes := make(chan string, requests)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			status, body := client.postJSON(t, "/api/v1/secret-links/consume", map[string]any{"token": created.Token}, map[string]string{
				"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", index+1),
			})
			statuses <- status
			if status == 200 {
				secret := body["secret"].(map[string]any)
				successes <- secret["value"].(string)
			}
		}(i)
	}
	wg.Wait()
	close(statuses)
	close(successes)

	ok := 0
	unavailable := 0
	for status := range statuses {
		switch status {
		case 200:
			ok++
		case 410, 409:
			unavailable++
		default:
			t.Fatalf("unexpected status %d", status)
		}
	}
	if ok != 1 || unavailable != requests-1 {
		t.Fatalf("successes=%d unavailable=%d", ok, unavailable)
	}
	if len(successes) != 1 {
		t.Fatalf("secret returned %d times, want once", len(successes))
	}
}

func TestUnavailableAndUnauthorizedIntegration(t *testing.T) {
	client := integrationClient(t)
	status, body := client.postJSON(t, "/api/v1/secret-links/consume", map[string]any{"token": "not-real"}, nil)
	if status != 410 || body["code"] != "SECRET_UNAVAILABLE" {
		t.Fatalf("invalid token = %d %#v, want generic 410", status, body)
	}

	status, _ = client.postJSON(t, "/api/v1/secret-links", map[string]any{"secret": "no auth"}, map[string]string{})
	if status != 401 {
		t.Fatalf("unauthorized create = %d, want 401", status)
	}
}

func TestRateLimitIntegration(t *testing.T) {
	client := integrationClient(t)
	token := "rate-limit-token"
	lastStatus := 0
	for i := 0; i < 11; i++ {
		status, _ := client.postJSON(t, "/api/v1/secret-links/consume", map[string]any{"token": token}, nil)
		lastStatus = status
	}
	if lastStatus != 429 {
		t.Fatalf("11th consume status = %d, want 429", lastStatus)
	}
}

type integration struct {
	baseURL     string
	adminKey    string
	databaseURL string
	http        *http.Client
}

type createdSecret struct {
	ID    string
	URL   string
	Token string
}

func integrationClient(t *testing.T) *integration {
	t.Helper()
	if os.Getenv("INTEGRATION_TESTS") != "1" {
		t.Skip("set INTEGRATION_TESTS=1 and start docker compose to run integration tests")
	}
	baseURL := getenv("APP_BASE_URL", "http://localhost:8080")
	client := &integration{
		baseURL:     strings.TrimRight(baseURL, "/"),
		adminKey:    getenv("SECURESHARE_ADMIN_API_KEY", "change-me"),
		databaseURL: getenv("INTEGRATION_DATABASE_URL", "postgres://secureshare:secureshare@localhost:5432/secureshare?sslmode=disable"),
		http:        &http.Client{Timeout: 10 * time.Second},
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.http.Get(client.baseURL + "/health/ready")
		if err == nil && resp.StatusCode == 200 {
			_ = resp.Body.Close()
			return client
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(time.Second)
	}
	t.Fatal("application did not become ready")
	return nil
}

func (c *integration) create(t *testing.T, payload map[string]any) createdSecret {
	t.Helper()
	status, body := c.postJSON(t, "/api/v1/secret-links", payload, map[string]string{
		"Authorization": "Bearer " + c.adminKey,
	})
	if status != 201 {
		t.Fatalf("create = %d %#v, want 201", status, body)
	}
	url := body["url"].(string)
	_, token, ok := strings.Cut(url, "#")
	if !ok || token == "" {
		t.Fatalf("url did not contain fragment token: %q", url)
	}
	return createdSecret{ID: body["id"].(string), URL: url, Token: token}
}

func (c *integration) postJSON(t *testing.T, path string, payload any, headers map[string]string) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func (c *integration) assertCiphertextOnly(t *testing.T, id string, marker string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, c.databaseURL)
	if err != nil {
		t.Fatalf("database connect failed: %v", err)
	}
	defer conn.Close(ctx)
	var encrypted string
	if err := conn.QueryRow(ctx, `SELECT encrypted_payload FROM secret_deliveries WHERE id = $1`, id).Scan(&encrypted); err != nil {
		t.Fatalf("query encrypted payload failed: %v", err)
	}
	if strings.Contains(encrypted, marker) {
		t.Fatal("database contained plaintext marker")
	}
	if !strings.HasPrefix(encrypted, "vault:v") {
		t.Fatalf("encrypted payload did not look like Vault ciphertext: %q", encrypted)
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func TestPayloadTooLargeIntegration(t *testing.T) {
	client := integrationClient(t)
	large := strings.Repeat("x", 33*1024)
	status, body := client.postJSON(t, "/api/v1/secret-links", map[string]any{
		"secret":             large,
		"expires_in_seconds": 900,
	}, map[string]string{"Authorization": "Bearer " + client.adminKey})
	if status != 413 {
		t.Fatalf("large payload = %d %#v, want 413", status, body)
	}
}

func Example() {
	fmt.Println("docker compose up -d --build && ./scripts/smoke-test.sh")
	// Output: docker compose up -d --build && ./scripts/smoke-test.sh
}
