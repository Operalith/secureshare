package email

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"secureshare/internal/observability"
)

func TestConnectionAuthenticatesWithoutSendingEmail(t *testing.T) {
	server := startFakeSMTP(t, fakeSMTPOptions{advertiseAuth: true})
	vault := &smtpTestVault{}
	service := configuredSMTPService(t, server, vault, false, EncryptionNone, "smtp-user", " password with spaces ")

	result := service.TestConnection(context.Background())
	if !result.OK || result.DurationMS < 1 {
		t.Fatalf("connection test = %+v, want successful attempted operation", result)
	}
	if vault.decrypts != 1 {
		t.Fatalf("password decrypts = %d, want 1", vault.decrypts)
	}
	if server.authentications() != 1 {
		t.Fatalf("SMTP authentications = %d, want 1", server.authentications())
	}
	if server.deliveries() != 0 {
		t.Fatalf("connection test sent %d messages, want 0", server.deliveries())
	}
}

func TestSendTestEmailUsesSavedConfigurationAndSafeBody(t *testing.T) {
	server := startFakeSMTP(t, fakeSMTPOptions{})
	service := configuredSMTPService(t, server, &smtpTestVault{}, false, EncryptionNone, "", "")

	result := service.SendTest(context.Background(), "recipient@example.local")
	if !result.OK || result.DurationMS < 1 {
		t.Fatalf("send test = %+v, want success", result)
	}
	if server.deliveries() != 1 {
		t.Fatalf("test deliveries = %d, want 1", server.deliveries())
	}
	message := server.lastMessage()
	for _, want := range []string{"SecureShare SMTP test", "safe SecureShare SMTP test message", "recipient@example.local"} {
		if !strings.Contains(message, want) {
			t.Fatalf("test message missing %q", want)
		}
	}
	for _, forbidden := range []string{" password with spaces ", "vault:v1:", "Authorization:"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("test message leaked %q", forbidden)
		}
	}
}

func TestDisabledSettingsBlockRoutineDeliveryButAllowExplicitAdminTests(t *testing.T) {
	server := startFakeSMTP(t, fakeSMTPOptions{})
	service := configuredSMTPService(t, server, &smtpTestVault{}, false, EncryptionNone, "", "")
	connection := service.TestConnection(context.Background())
	if !connection.OK {
		t.Fatalf("disabled connection test = %+v, want success", connection)
	}
	rendered := RenderedTemplate{Subject: "Routine delivery", Text: "safe body"}
	result := service.SendRendered(context.Background(), SendRenderedRequest{To: "recipient@example.local", Rendered: rendered})
	if result.OK || result.Code != CategoryConfigurationError || result.Fields["enabled"] == "" {
		t.Fatalf("disabled routine delivery = %+v, want safe enabled field error", result)
	}
	if server.deliveries() != 0 {
		t.Fatalf("disabled routine delivery sent %d messages", server.deliveries())
	}
}

func TestSMTPConfigurationErrorsAreSafeAndFieldSpecific(t *testing.T) {
	service := NewService(testConfig("development"), NewMemoryStore(), &smtpTestVault{}, observability.New(), nil)
	result := service.TestConnection(context.Background())
	if result.OK || result.Code != CategoryConfigurationError || result.ErrorCategory != CategoryConfigurationError {
		t.Fatalf("configuration result = %+v", result)
	}
	for _, field := range []string{"smtp_host", "smtp_port", "from_email"} {
		if result.Fields[field] == "" {
			t.Fatalf("configuration response missing safe field error for %s: %+v", field, result)
		}
	}
	if result.DurationMS > 50 {
		t.Fatalf("pre-network configuration duration = %dms, want immediate safe validation", result.DurationMS)
	}

	request := validUpdateRequest()
	request.SMTPPassword = "configured-password"
	request.SMTPHost = "https://smtp.example.local"
	_, err := service.Update(context.Background(), uuidForTest(), request)
	var validationErr *ValidationError
	if err == nil || !errors.As(err, &validationErr) || validationErr.Fields["smtp_host"] == "" {
		t.Fatalf("invalid host error = %v, fields=%v", err, validationErr)
	}
}

func TestSMTPFailureCategoryMapping(t *testing.T) {
	t.Run("connection", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		_ = listener.Close()
		service := configuredSMTPServiceForAddress(t, address, &smtpTestVault{}, EncryptionNone, "", "")
		assertSMTPFailure(t, service.TestConnection(context.Background()), CategoryConnectionFailed)
	})

	t.Run("starttls", func(t *testing.T) {
		server := startFakeSMTP(t, fakeSMTPOptions{})
		service := configuredSMTPService(t, server, &smtpTestVault{}, false, EncryptionStartTLS, "", "")
		assertSMTPFailure(t, service.TestConnection(context.Background()), CategoryTLSFailed)
	})

	t.Run("authentication", func(t *testing.T) {
		server := startFakeSMTP(t, fakeSMTPOptions{advertiseAuth: true, rejectAuth: true})
		vault := &smtpTestVault{}
		service := configuredSMTPService(t, server, vault, false, EncryptionNone, "smtp-user", "smtp-password-canary")
		assertSMTPFailure(t, service.TestConnection(context.Background()), CategoryAuthenticationFailed)
		if vault.decrypts != 1 {
			t.Fatalf("password decrypts = %d, want 1", vault.decrypts)
		}
	})

	t.Run("password decrypt", func(t *testing.T) {
		server := startFakeSMTP(t, fakeSMTPOptions{advertiseAuth: true})
		vault := &failingSMTPVault{}
		service := configuredSMTPService(t, server, vault, false, EncryptionNone, "smtp-user", "smtp-password-canary")
		result := service.TestConnection(context.Background())
		assertSMTPFailure(t, result, CategoryConfigurationError)
		if strings.Contains(result.Message, "vault-decrypt-canary") {
			t.Fatalf("Vault error leaked in result: %+v", result)
		}
	})

	t.Run("recipient", func(t *testing.T) {
		server := startFakeSMTP(t, fakeSMTPOptions{rejectRecipient: true})
		service := configuredSMTPService(t, server, &smtpTestVault{}, false, EncryptionNone, "", "")
		assertSMTPFailure(t, service.SendTest(context.Background(), "recipient@example.local"), CategoryRecipientRejected)
	})

	t.Run("timeout", func(t *testing.T) {
		server := startFakeSMTP(t, fakeSMTPOptions{stallOnCommand: "DATA"})
		service := configuredSMTPService(t, server, &smtpTestVault{}, false, EncryptionNone, "", "")
		result := service.SendTest(context.Background(), "recipient@example.local")
		assertSMTPFailure(t, result, CategoryTimeout)
		if result.DurationMS < 900 {
			t.Fatalf("timeout duration = %dms, want a real attempted timeout", result.DurationMS)
		}
	})
}

func TestSMTPServiceLogsDoNotContainCredentialsRecipientOrBody(t *testing.T) {
	server := startFakeSMTP(t, fakeSMTPOptions{advertiseAuth: true, rejectAuth: true})
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	vault := &smtpTestVault{}
	service := NewService(testConfig("development"), NewMemoryStore(), vault, observability.New(), logger)
	request := smtpUpdateRequest(server.address(), EncryptionNone, "smtp-user", "smtp-password-canary")
	if _, err := service.Update(context.Background(), uuidForTest(), request); err != nil {
		t.Fatal(err)
	}
	_ = service.SendTest(context.Background(), "recipient-canary@example.local")
	for _, forbidden := range []string{"smtp-password-canary", "recipient-canary@example.local", "safe SecureShare SMTP test message", "vault:v1:"} {
		if strings.Contains(logs.String(), forbidden) {
			t.Fatalf("service logs leaked %q: %s", forbidden, logs.String())
		}
	}
}

func assertSMTPFailure(t *testing.T, result ConnectionTestResult, category string) {
	t.Helper()
	if result.OK || result.ErrorCategory != category || result.Code != category || result.Message == "" || result.DurationMS < 1 {
		t.Fatalf("SMTP result = %+v, want safe %s failure with attempted duration", result, category)
	}
}

func configuredSMTPService(t *testing.T, server *fakeSMTPServer, vault Vault, enabled bool, mode, username, password string) *Service {
	t.Helper()
	service := configuredSMTPServiceForAddress(t, server.address(), vault, mode, username, password)
	if enabled {
		stored := service.store.(*MemoryStore).StoredForTest()
		stored.Enabled = true
		if _, err := service.store.SaveSettings(context.Background(), stored); err != nil {
			t.Fatal(err)
		}
	}
	return service
}

func configuredSMTPServiceForAddress(t *testing.T, address string, vault Vault, mode, username, password string) *Service {
	t.Helper()
	service := NewService(testConfig("development"), NewMemoryStore(), vault, observability.New(), nil)
	request := smtpUpdateRequest(address, mode, username, password)
	if _, err := service.Update(context.Background(), uuidForTest(), request); err != nil {
		t.Fatalf("save SMTP settings: %v", err)
	}
	return service
}

func smtpUpdateRequest(address, mode, username, password string) UpdateRequest {
	host, portValue, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portValue)
	return UpdateRequest{
		Enabled:                  false,
		SMTPHost:                 host,
		SMTPPort:                 port,
		EncryptionMode:           mode,
		SMTPUsername:             username,
		SMTPPassword:             password,
		FromName:                 "SecureShare Tests",
		FromEmail:                "secureshare@example.local",
		ReplyToEmail:             "support@example.local",
		ConnectionTimeoutSeconds: 1,
		SendTimeoutSeconds:       1,
		DefaultSubject:           DefaultSubject,
		DefaultMessage:           DefaultMessage,
	}
}

type smtpTestVault struct {
	mu       sync.Mutex
	password string
	decrypts int
}

func (v *smtpTestVault) Encrypt(_ context.Context, value []byte) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.password = string(value)
	return "vault:v1:smtp-test-ciphertext", nil
}

func (v *smtpTestVault) Decrypt(_ context.Context, _ string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.decrypts++
	return []byte(v.password), nil
}

func (v *smtpTestVault) Ready(context.Context) error { return nil }

type failingSMTPVault struct{ smtpTestVault }

func (v *failingSMTPVault) Decrypt(context.Context, string) ([]byte, error) {
	return nil, errors.New("vault-decrypt-canary")
}

type fakeSMTPOptions struct {
	advertiseAuth   bool
	rejectAuth      bool
	rejectRecipient bool
	stallOnCommand  string
}

type fakeSMTPServer struct {
	listener net.Listener
	options  fakeSMTPOptions
	mu       sync.Mutex
	auths    int
	messages []string
}

func startFakeSMTP(t *testing.T, options fakeSMTPOptions) *fakeSMTPServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &fakeSMTPServer{listener: listener, options: options}
	go server.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return server
}

func (s *fakeSMTPServer) address() string { return s.listener.Addr().String() }

func (s *fakeSMTPServer) authentications() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auths
}

func (s *fakeSMTPServer) deliveries() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

func (s *fakeSMTPServer) lastMessage() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.messages) == 0 {
		return ""
	}
	return s.messages[len(s.messages)-1]
}

func (s *fakeSMTPServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	writeSMTPLine(writer, "220 localhost ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.ToUpper(strings.TrimSpace(line))
		if s.options.stallOnCommand != "" && strings.HasPrefix(command, s.options.stallOnCommand) {
			time.Sleep(2 * time.Second)
			return
		}
		switch {
		case strings.HasPrefix(command, "EHLO"):
			if s.options.advertiseAuth {
				_, _ = fmt.Fprint(writer, "250-localhost\r\n250 AUTH PLAIN\r\n")
				_ = writer.Flush()
			} else {
				writeSMTPLine(writer, "250 localhost")
			}
		case strings.HasPrefix(command, "HELO"):
			writeSMTPLine(writer, "250 localhost")
		case strings.HasPrefix(command, "AUTH"):
			s.mu.Lock()
			s.auths++
			s.mu.Unlock()
			if s.options.rejectAuth {
				writeSMTPLine(writer, "535 5.7.8 Authentication failed")
			} else {
				writeSMTPLine(writer, "235 2.7.0 Authentication successful")
			}
		case strings.HasPrefix(command, "MAIL FROM"):
			writeSMTPLine(writer, "250 2.1.0 Sender accepted")
		case strings.HasPrefix(command, "RCPT TO"):
			if s.options.rejectRecipient {
				writeSMTPLine(writer, "550 5.1.1 Recipient rejected")
			} else {
				writeSMTPLine(writer, "250 2.1.5 Recipient accepted")
			}
		case command == "DATA":
			writeSMTPLine(writer, "354 End data with <CR><LF>.<CR><LF>")
			message, err := textproto.NewReader(reader).ReadDotBytes()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.messages = append(s.messages, string(message))
			s.mu.Unlock()
			writeSMTPLine(writer, "250 2.0.0 Message accepted")
		case command == "QUIT":
			writeSMTPLine(writer, "221 2.0.0 Bye")
			return
		default:
			writeSMTPLine(writer, "250 2.0.0 OK")
		}
	}
}

func writeSMTPLine(writer *bufio.Writer, line string) {
	_, _ = io.WriteString(writer, line+"\r\n")
	_ = writer.Flush()
}
