package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

func TestFlexibleStructuredPayloadIntegration(t *testing.T) {
	client := integrationClient(t)
	marker := "integration-api-key-value"
	created := client.create(t, map[string]any{
		"title":              "Mixed credential payload",
		"expires_in_seconds": 900,
		"payload": map[string]any{
			"type": "structured",
			"fields": []map[string]any{
				{"name": "username", "label": "Username", "value": "merchant-1001", "sensitive": false, "multiline": false},
				{"name": "password", "label": "Password", "value": "temporary-password", "sensitive": true, "multiline": false},
				{"name": "api_key", "label": "API Key", "value": marker, "sensitive": true, "multiline": false},
			},
		},
	})

	status, _, raw := client.getJSON(t, "/api/v1/secret-links/"+created.ID, map[string]string{
		"Authorization": "Bearer " + client.adminKey,
	})
	if status != 200 {
		t.Fatalf("metadata status = %d, want 200", status)
	}
	if strings.Contains(raw, marker) || strings.Contains(raw, "temporary-password") {
		t.Fatal("metadata response contained secret field values")
	}

	status, body := client.postJSON(t, "/api/v1/secret-links/consume", map[string]any{"token": created.Token}, nil)
	if status != 200 {
		t.Fatalf("consume = %d %#v, want 200", status, body)
	}
	payload := body["payload"].(map[string]any)
	if payload["type"] != "structured" {
		t.Fatalf("payload type = %#v, want structured", payload["type"])
	}
	fields := payload["fields"].([]any)
	if len(fields) != 3 {
		t.Fatalf("fields = %d, want 3", len(fields))
	}
	legacy := body["secret"].(map[string]any)
	if legacy["api_key"] != marker || legacy["username"] != "merchant-1001" {
		t.Fatalf("legacy projection = %#v", legacy)
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

func TestSMTPEmailDeliveryIntegration(t *testing.T) {
	client := integrationClient(t)
	if !client.testSMTPEnabled {
		t.Skip("set TEST_SMTP_ENABLED=true and provide Mailpit to run SMTP capture checks")
	}
	client.clearMailpit(t)
	client.configureSMTP(t)

	status, body := client.postJSON(t, "/api/v1/settings/email/test-connection", map[string]any{}, map[string]string{
		"Authorization": "Bearer " + client.adminKey,
	})
	if status != 200 || body["ok"] != true {
		t.Fatalf("SMTP connection test = %d %#v, want ok", status, body)
	}

	status, body = client.postJSON(t, "/api/v1/settings/email/send-test", map[string]any{"to": "integration-recipient@example.local"}, map[string]string{
		"Authorization": "Bearer " + client.adminKey,
	})
	if status != 200 || body["ok"] != true {
		t.Fatalf("SMTP test delivery = %d %#v, want ok", status, body)
	}

	username := "integration-user-" + client.runID
	password := "integration-password-" + client.runID
	apiKey := "integration-api-key-" + client.runID
	created := client.create(t, map[string]any{
		"title":              "Integration SMTP delivery",
		"expires_in_seconds": 900,
		"payload": map[string]any{
			"type": "structured",
			"fields": []map[string]any{
				{"name": "username", "label": "Username", "value": username, "sensitive": false, "multiline": false},
				{"name": "password", "label": "Password", "value": password, "sensitive": true, "multiline": false},
				{"name": "api_key", "label": "API Key", "value": apiKey, "sensitive": true, "multiline": false},
			},
		},
		"delivery": map[string]any{
			"email": map[string]any{
				"send":                 true,
				"to":                   "integration-recipient@example.local",
				"recipient_name":       "Integration Recipient",
				"use_default_template": false,
				"subject":              "Integration secure package",
				"message":              "Hello {{recipient_name}},\n\nIntegration custom delivery message.\n\n{{secure_link}}\n\nExpires at {{expires_at}}.",
			},
		},
	})

	client.assertMailpitMessage(t, "Integration secure package", "Integration custom delivery message", []string{username, password, apiKey})

	status, body = client.postJSON(t, "/api/v1/secret-links/consume", map[string]any{"token": created.Token}, nil)
	if status != 200 {
		t.Fatalf("consume emailed secret = %d %#v, want 200", status, body)
	}
	payload := body["payload"].(map[string]any)
	fields := payload["fields"].([]any)
	seen := map[string]string{}
	for _, rawField := range fields {
		field := rawField.(map[string]any)
		seen[field["name"].(string)] = field["value"].(string)
	}
	if seen["username"] != username || seen["password"] != password || seen["api_key"] != apiKey {
		t.Fatalf("consumed payload = %#v, want all credential fields once", seen)
	}
	status, body = client.postJSON(t, "/api/v1/secret-links/consume", map[string]any{"token": created.Token}, nil)
	if status != 410 || body["code"] != "SECRET_UNAVAILABLE" {
		t.Fatalf("second consume emailed secret = %d %#v, want generic 410", status, body)
	}
}

type integration struct {
	baseURL         string
	adminKey        string
	databaseURL     string
	runID           string
	testSMTPEnabled bool
	testSMTPHost    string
	testSMTPPort    int
	mailpitURL      string
	http            *http.Client
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
		baseURL:         strings.TrimRight(baseURL, "/"),
		adminKey:        getenv("SECURESHARE_ADMIN_API_KEY", "change-me"),
		databaseURL:     getenv("INTEGRATION_DATABASE_URL", "postgres://secureshare:secureshare@localhost:5432/secureshare?sslmode=disable"),
		runID:           getenv("SECURESHARE_TEST_RUN_ID", fmt.Sprintf("integration-test-%d", time.Now().UnixNano())),
		testSMTPEnabled: getenv("TEST_SMTP_ENABLED", "false") == "true",
		testSMTPHost:    getenv("TEST_SMTP_HOST", "mailpit"),
		testSMTPPort:    getenvInt("TEST_SMTP_PORT", 1025),
		mailpitURL:      strings.TrimRight(getenv("MAILPIT_API_URL", "http://localhost:8025"), "/"),
		http:            &http.Client{Timeout: 10 * time.Second},
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
	if _, ok := payload["recipient_reference"]; !ok {
		payload["recipient_reference"] = c.runID
	}
	if title, ok := payload["title"].(string); ok && !strings.Contains(title, c.runID) {
		payload["title"] = title + " " + c.runID
	}
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
	return c.doJSON(t, http.MethodPost, path, payload, headers)
}

func (c *integration) putJSON(t *testing.T, path string, payload any, headers map[string]string) (int, map[string]any) {
	t.Helper()
	return c.doJSON(t, http.MethodPut, path, payload, headers)
}

func (c *integration) doJSON(t *testing.T, method, path string, payload any, headers map[string]string) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, c.baseURL+path, bytes.NewReader(raw))
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

func (c *integration) getJSON(t *testing.T, path string, headers map[string]string) (int, map[string]any, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rawBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(rawBytes)
	var body map[string]any
	_ = json.Unmarshal(rawBytes, &body)
	return resp.StatusCode, body, raw
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

func (c *integration) assertAuditEvent(t *testing.T, eventType string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, c.databaseURL)
	if err != nil {
		t.Fatalf("database connect failed: %v", err)
	}
	defer conn.Close(ctx)
	var count int
	if err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE event_type = $1`, eventType).Scan(&count); err != nil {
		t.Fatalf("query audit event failed: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected audit event %s", eventType)
	}
}

func (c *integration) configureSMTP(t *testing.T) {
	t.Helper()
	status, body := c.putJSON(t, "/api/v1/settings/email", map[string]any{
		"enabled":                    true,
		"smtp_host":                  c.testSMTPHost,
		"smtp_port":                  c.testSMTPPort,
		"encryption_mode":            "none",
		"smtp_username":              "",
		"smtp_password":              "",
		"from_name":                  "SecureShare Integration Tests",
		"from_email":                 "secureshare-tests@example.local",
		"reply_to_email":             "support@example.local",
		"connection_timeout_seconds": 5,
		"send_timeout_seconds":       10,
		"default_subject":            "SecureShare default integration message",
		"default_message":            "Hello {{recipient_name}},\n\nUse {{secure_link}} to open the integration test secret.\n\nRegards,\n{{sender_name}}",
		"footer_text":                "Development-only captured email",
	}, map[string]string{
		"Authorization": "Bearer " + c.adminKey,
	})
	if status != 200 {
		t.Fatalf("configure SMTP = %d %#v, want 200", status, body)
	}
}

func (c *integration) clearMailpit(t *testing.T) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, c.mailpitURL+"/api/v1/messages", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("clear Mailpit failed: %v", err)
	}
	_ = resp.Body.Close()
}

func (c *integration) assertMailpitMessage(t *testing.T, subject, expected string, forbidden []string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		rawListing, messages, err := c.mailpitMessages()
		if err != nil {
			last = err.Error()
			time.Sleep(time.Second)
			continue
		}
		for _, message := range messages {
			if !strings.Contains(message.Subject, subject) {
				continue
			}
			combined := rawListing
			if message.ID != "" {
				if detail, err := c.mailpitGet("/api/v1/message/" + url.PathEscape(message.ID)); err == nil {
					combined += "\n" + detail
				}
				if raw, err := c.mailpitGet("/api/v1/message/" + url.PathEscape(message.ID) + "/raw"); err == nil {
					combined += "\n" + raw
				}
			}
			if !strings.Contains(combined, expected) {
				t.Fatalf("captured email missing %q", expected)
			}
			if !strings.Contains(combined, "integration-recipient@example.local") {
				t.Fatal("captured email missing recipient")
			}
			if !strings.Contains(combined, c.baseURL+"/s#") {
				t.Fatal("captured email missing fragment secure link")
			}
			lower := strings.ToLower(combined)
			if !strings.Contains(lower, "text/plain") && !strings.Contains(lower, `"text"`) {
				t.Fatal("captured email missing plain-text body")
			}
			if !strings.Contains(lower, "text/html") && !strings.Contains(lower, `"html"`) {
				t.Fatal("captured email missing HTML body")
			}
			for _, value := range forbidden {
				if value != "" && strings.Contains(combined, value) {
					t.Fatalf("captured email leaked forbidden value %q", value)
				}
			}
			return
		}
		last = rawListing
		time.Sleep(time.Second)
	}
	t.Fatalf("Mailpit did not capture subject %q: %s", subject, last)
}

type mailpitMessage struct {
	ID      string
	Subject string
}

func (c *integration) mailpitMessages() (string, []mailpitMessage, error) {
	raw, err := c.mailpitGet("/api/v1/messages")
	if err != nil {
		return "", nil, err
	}
	var listing struct {
		Messages []mailpitMessage `json:"messages"`
	}
	if err := json.Unmarshal([]byte(raw), &listing); err != nil {
		return raw, nil, err
	}
	return raw, listing.Messages, nil
}

func (c *integration) mailpitGet(path string) (string, error) {
	resp, err := c.http.Get(c.mailpitURL + path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return string(raw), fmt.Errorf("mailpit %s returned %d", path, resp.StatusCode)
	}
	return string(raw), nil
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	var parsed int
	if _, err := fmt.Sscanf(value, "%d", &parsed); err != nil {
		return fallback
	}
	return parsed
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

func TestAdminManagementAPIsIntegration(t *testing.T) {
	client := integrationClient(t)
	alpha := client.create(t, map[string]any{
		"title":               "Alpha searchable credentials",
		"recipient_reference": "merchant-alpha",
		"secret":              map[string]any{"value": "alpha-management-secret"},
		"expires_in_seconds":  900,
	})
	revoked := client.create(t, map[string]any{
		"title":               "Revoked management credentials",
		"recipient_reference": "merchant-revoked",
		"secret":              map[string]any{"value": "revoked-management-secret"},
		"expires_in_seconds":  900,
	})
	consumed := client.create(t, map[string]any{
		"title":               "Consumed management credentials",
		"recipient_reference": "merchant-consumed",
		"secret":              map[string]any{"value": "consumed-management-secret"},
		"expires_in_seconds":  900,
	})

	status, _ := client.postJSON(t, "/api/v1/secret-links/"+revoked.ID+"/revoke", map[string]any{}, map[string]string{"Authorization": "Bearer " + client.adminKey})
	if status != 200 {
		t.Fatalf("revoke status = %d, want 200", status)
	}
	status, _ = client.postJSON(t, "/api/v1/secret-links/consume", map[string]any{"token": consumed.Token}, nil)
	if status != 200 {
		t.Fatalf("consume status = %d, want 200", status)
	}

	status, body, raw := client.getJSON(t, "/api/v1/secret-links?page_size=10&search=Alpha&sort=created_at&order=desc", map[string]string{"Authorization": "Bearer " + client.adminKey})
	if status != 200 {
		t.Fatalf("list status = %d %#v", status, body)
	}
	items := body["items"].([]any)
	if len(items) == 0 {
		t.Fatal("search list returned no items")
	}
	first := items[0].(map[string]any)
	if first["id"] != alpha.ID {
		t.Fatalf("search first id = %v, want %s", first["id"], alpha.ID)
	}
	for _, forbidden := range []string{"alpha-management-secret", alpha.Token, "vault:v", "token_hash", "password_hash", "encrypted_payload"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("list response contained sensitive value %q: %s", forbidden, raw)
		}
	}

	status, body, _ = client.getJSON(t, "/api/v1/secret-links?status=revoked&page_size=10", map[string]string{"Authorization": "Bearer " + client.adminKey})
	if status != 200 {
		t.Fatalf("revoked list status = %d", status)
	}
	foundRevoked := false
	for _, item := range body["items"].([]any) {
		row := item.(map[string]any)
		if row["id"] == revoked.ID && row["status"] == "revoked" {
			foundRevoked = true
		}
	}
	if !foundRevoked {
		t.Fatal("revoked filter did not include revoked secret")
	}

	status, body, _ = client.getJSON(t, "/api/v1/dashboard", map[string]string{"Authorization": "Bearer " + client.adminKey})
	if status != 200 {
		t.Fatalf("dashboard status = %d %#v", status, body)
	}
	if _, ok := body["active_count"]; !ok {
		t.Fatalf("dashboard missing counts: %#v", body)
	}
	deps := body["dependencies"].(map[string]any)
	if deps["postgres"] != "healthy" || deps["vault"] != "healthy" {
		t.Fatalf("dashboard dependency state = %#v, want healthy", deps)
	}

	status, body = client.postJSON(t, "/api/v1/admin/cleanup", map[string]any{}, map[string]string{"Authorization": "Bearer " + client.adminKey})
	if status != 200 || body["ok"] != true {
		t.Fatalf("manual cleanup = %d %#v, want ok", status, body)
	}

	client.assertAuditEvent(t, "secret.created")
	client.assertAuditEvent(t, "secret.consumed")
	client.assertAuditEvent(t, "secret.revoked")
}

func TestRevokeIdempotencyAndConsumedHistoryIntegration(t *testing.T) {
	client := integrationClient(t)
	active := client.create(t, map[string]any{
		"title":              "Idempotent revoke",
		"secret":             map[string]any{"value": "idempotent-secret"},
		"expires_in_seconds": 900,
	})
	status, body := client.postJSON(t, "/api/v1/secret-links/"+active.ID+"/revoke", map[string]any{}, map[string]string{"Authorization": "Bearer " + client.adminKey})
	if status != 200 || body["status"] != "revoked" {
		t.Fatalf("first revoke = %d %#v", status, body)
	}
	status, body = client.postJSON(t, "/api/v1/secret-links/"+active.ID+"/revoke", map[string]any{}, map[string]string{"Authorization": "Bearer " + client.adminKey})
	if status != 200 || body["status"] != "revoked" {
		t.Fatalf("second revoke = %d %#v, want idempotent revoked", status, body)
	}

	consumed := client.create(t, map[string]any{
		"title":              "Consumed not revoked",
		"secret":             map[string]any{"value": "consumed-history-secret"},
		"expires_in_seconds": 900,
	})
	status, _ = client.postJSON(t, "/api/v1/secret-links/consume", map[string]any{"token": consumed.Token}, nil)
	if status != 200 {
		t.Fatalf("consume before revoke = %d, want 200", status)
	}
	status, body = client.postJSON(t, "/api/v1/secret-links/"+consumed.ID+"/revoke", map[string]any{}, map[string]string{"Authorization": "Bearer " + client.adminKey})
	if status != 200 || body["status"] != "consumed" {
		t.Fatalf("revoke consumed = %d %#v, want consumed status", status, body)
	}
	status, body, _ = client.getJSON(t, "/api/v1/secret-links/"+consumed.ID, map[string]string{"Authorization": "Bearer " + client.adminKey})
	if status != 200 || body["status"] != "consumed" {
		t.Fatalf("metadata after consumed revoke = %d %#v, want consumed", status, body)
	}
}

func TestUnauthorizedListingIntegration(t *testing.T) {
	client := integrationClient(t)
	status, _, _ := client.getJSON(t, "/api/v1/secret-links", map[string]string{})
	if status != 401 {
		t.Fatalf("unauthorized list = %d, want 401", status)
	}
}

func Example() {
	fmt.Println("docker compose up -d --build && ./scripts/smoke-test.sh")
	// Output: docker compose up -d --build && ./scripts/smoke-test.sh
}
