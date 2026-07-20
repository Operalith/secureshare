package email

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/google/uuid"

	"secureshare/internal/config"
	"secureshare/internal/observability"
)

type Vault interface {
	Encrypt(context.Context, []byte) (string, error)
	Decrypt(context.Context, string) ([]byte, error)
	Ready(context.Context) error
}

type Service struct {
	cfg     config.Config
	store   Store
	vault   Vault
	metrics *observability.Metrics
	logger  *slog.Logger
}

func NewService(cfg config.Config, store Store, vault Vault, metrics *observability.Metrics, logger *slog.Logger) *Service {
	return &Service{cfg: cfg, store: store, vault: vault, metrics: metrics, logger: logger}
}

func (s *Service) SafeSettings(ctx context.Context) (Settings, error) {
	stored, err := s.store.GetSettings(ctx)
	if errors.Is(err, ErrNotConfigured) {
		return safeSettings(defaultStoredSettings()), nil
	}
	if err != nil {
		return Settings{}, err
	}
	return safeSettings(stored), nil
}

func (s *Service) Update(ctx context.Context, actorUserID uuid.UUID, req UpdateRequest) (UpdateResult, error) {
	current, err := s.store.GetSettings(ctx)
	if errors.Is(err, ErrNotConfigured) {
		current = defaultStoredSettings()
	} else if err != nil {
		return UpdateResult{}, err
	}

	next := StoredSettings{
		Settings: Settings{
			ID:                       SingletonID,
			Enabled:                  req.Enabled,
			SMTPHost:                 strings.TrimSpace(req.SMTPHost),
			SMTPPort:                 req.SMTPPort,
			EncryptionMode:           strings.TrimSpace(strings.ToLower(req.EncryptionMode)),
			SMTPUsername:             strings.TrimSpace(req.SMTPUsername),
			FromName:                 strings.TrimSpace(req.FromName),
			FromEmail:                strings.TrimSpace(strings.ToLower(req.FromEmail)),
			ReplyToEmail:             strings.TrimSpace(strings.ToLower(req.ReplyToEmail)),
			ConnectionTimeoutSeconds: req.ConnectionTimeoutSeconds,
			SendTimeoutSeconds:       req.SendTimeoutSeconds,
			DefaultSubject:           strings.TrimSpace(req.DefaultSubject),
			DefaultMessage:           strings.TrimSpace(req.DefaultMessage),
			FooterText:               strings.TrimSpace(req.FooterText),
			UpdatedBy:                &actorUserID,
			CreatedAt:                current.CreatedAt,
			UpdatedAt:                current.UpdatedAt,
		},
		SMTPPasswordCiphertext: current.SMTPPasswordCiphertext,
	}
	normalizeSettings(&next.Settings)
	if actorUserID == uuid.Nil {
		next.UpdatedBy = nil
	}
	if err := s.validate(next.Settings); err != nil {
		return UpdateResult{}, err
	}

	result := UpdateResult{}
	password := strings.TrimSpace(req.SMTPPassword)
	if req.ClearSMTPPassword {
		next.SMTPPasswordCiphertext = ""
		result.PasswordCleared = current.SMTPPasswordCiphertext != ""
	} else if password != "" {
		ciphertext, err := s.vault.Encrypt(ctx, []byte(password))
		if err != nil {
			return UpdateResult{}, fmt.Errorf("%w: SMTP password encryption failed", ErrDependency)
		}
		next.SMTPPasswordCiphertext = ciphertext
		result.PasswordUpdated = true
	}
	next.PasswordConfigured = next.SMTPPasswordCiphertext != ""
	saved, err := s.store.SaveSettings(ctx, next)
	if err != nil {
		return UpdateResult{}, err
	}
	result.Settings = safeSettings(saved)
	return result, nil
}

func (s *Service) SetEnabled(ctx context.Context, actorUserID uuid.UUID, enabled bool) (Settings, error) {
	current, err := s.store.GetSettings(ctx)
	if err != nil {
		return Settings{}, err
	}
	current.Enabled = enabled
	current.UpdatedBy = &actorUserID
	if actorUserID == uuid.Nil {
		current.UpdatedBy = nil
	}
	if err := s.validate(current.Settings); err != nil {
		return Settings{}, err
	}
	saved, err := s.store.SaveSettings(ctx, current)
	if err != nil {
		return Settings{}, err
	}
	return safeSettings(saved), nil
}

func (s *Service) TestConnection(ctx context.Context) ConnectionTestResult {
	start := time.Now()
	stored, err := s.store.GetSettings(ctx)
	if err != nil {
		return s.connectionResult(start, false, EncryptionStartTLS, "SMTP_CONFIGURATION_ERROR")
	}
	if err := s.validate(stored.Settings); err != nil {
		return s.connectionResult(start, false, stored.EncryptionMode, "SMTP_CONFIGURATION_ERROR")
	}
	result := s.connectAndAuthenticate(ctx, stored)
	result.DurationMS = time.Since(start).Milliseconds()
	if s.metrics != nil {
		status := "success"
		if !result.OK {
			status = "failed"
			s.metrics.SMTPConnectionErrors.WithLabelValues(result.ErrorCategory, result.EncryptionMode).Inc()
		}
		s.metrics.SMTPConnectionTests.WithLabelValues(status, result.EncryptionMode).Inc()
		s.metrics.SMTPConnectionDuration.WithLabelValues(status, result.EncryptionMode).Observe(time.Since(start).Seconds())
	}
	return result
}

func (s *Service) SendTest(ctx context.Context, to string) ConnectionTestResult {
	start := time.Now()
	stored, err := s.store.GetSettings(ctx)
	if err != nil {
		return s.connectionResult(start, false, EncryptionStartTLS, "SMTP_CONFIGURATION_ERROR")
	}
	if err := s.validate(stored.Settings); err != nil {
		return s.connectionResult(start, false, stored.EncryptionMode, "SMTP_CONFIGURATION_ERROR")
	}
	if _, err := mail.ParseAddress(strings.TrimSpace(to)); err != nil {
		return s.connectionResult(start, false, stored.EncryptionMode, "SMTP_RECIPIENT_REJECTED")
	}
	result := s.sendMail(ctx, stored, strings.TrimSpace(to), "SecureShare SMTP test", "This is a safe SecureShare SMTP test message. It does not contain a secret or one-time link.", "")
	result.DurationMS = time.Since(start).Milliseconds()
	if s.metrics != nil {
		status := "success"
		if !result.OK {
			status = "failed"
		}
		s.metrics.EmailTestDeliveries.WithLabelValues(status).Inc()
	}
	return result
}

func (s *Service) SendRendered(ctx context.Context, req SendRenderedRequest) ConnectionTestResult {
	start := time.Now()
	stored, err := s.store.GetSettings(ctx)
	if err != nil {
		return s.connectionResult(start, false, EncryptionStartTLS, "SMTP_CONFIGURATION_ERROR")
	}
	if err := s.validate(stored.Settings); err != nil || !stored.Enabled {
		return s.connectionResult(start, false, stored.EncryptionMode, "SMTP_CONFIGURATION_ERROR")
	}
	to := strings.TrimSpace(req.To)
	if _, err := mail.ParseAddress(to); err != nil {
		return s.connectionResult(start, false, stored.EncryptionMode, "SMTP_RECIPIENT_REJECTED")
	}
	result := s.sendMail(ctx, stored, to, req.Rendered.Subject, req.Rendered.Text, req.Rendered.HTML)
	result.DurationMS = time.Since(start).Milliseconds()
	return result
}

func (s *Service) connectionResult(start time.Time, ok bool, mode, category string) ConnectionTestResult {
	result := "success"
	if !ok {
		result = "failed"
	}
	return ConnectionTestResult{
		OK:             ok,
		Result:         result,
		ErrorCategory:  category,
		EncryptionMode: mode,
		DurationMS:     time.Since(start).Milliseconds(),
	}
}

func (s *Service) validate(settings Settings) error {
	if settings.EncryptionMode != EncryptionStartTLS && settings.EncryptionMode != EncryptionTLS && settings.EncryptionMode != EncryptionNone {
		return fmt.Errorf("%w: invalid encryption mode", ErrInvalid)
	}
	if s.cfg.AppEnv == "production" && settings.EncryptionMode == EncryptionNone {
		return fmt.Errorf("%w: unencrypted SMTP is not allowed in production", ErrForbidden)
	}
	if settings.Enabled {
		if settings.SMTPHost == "" || settings.SMTPPort <= 0 || settings.SMTPPort > 65535 {
			return fmt.Errorf("%w: SMTP host and port are required", ErrInvalid)
		}
		if _, err := mail.ParseAddress(settings.FromEmail); err != nil {
			return fmt.Errorf("%w: sender email is invalid", ErrInvalid)
		}
		if settings.ReplyToEmail != "" {
			if _, err := mail.ParseAddress(settings.ReplyToEmail); err != nil {
				return fmt.Errorf("%w: reply-to email is invalid", ErrInvalid)
			}
		}
	}
	if settings.SMTPPort < 0 || settings.SMTPPort > 65535 {
		return fmt.Errorf("%w: invalid SMTP port", ErrInvalid)
	}
	if settings.ConnectionTimeoutSeconds <= 0 || settings.ConnectionTimeoutSeconds > 60 {
		return fmt.Errorf("%w: invalid connection timeout", ErrInvalid)
	}
	if settings.SendTimeoutSeconds <= 0 || settings.SendTimeoutSeconds > 120 {
		return fmt.Errorf("%w: invalid send timeout", ErrInvalid)
	}
	if settings.DefaultSubject == "" || len(settings.DefaultSubject) > 255 {
		return fmt.Errorf("%w: invalid default subject", ErrInvalid)
	}
	if settings.DefaultMessage == "" || len(settings.DefaultMessage) > 10*1024 {
		return fmt.Errorf("%w: invalid default message", ErrInvalid)
	}
	if len(settings.FooterText) > 2*1024 {
		return fmt.Errorf("%w: invalid footer", ErrInvalid)
	}
	return nil
}

func (s *Service) connectAndAuthenticate(ctx context.Context, stored StoredSettings) ConnectionTestResult {
	client, closeFn, category := s.smtpClient(ctx, stored)
	if category != "" {
		return s.connectionResult(time.Now(), false, stored.EncryptionMode, category)
	}
	defer closeFn()
	if err := s.authenticate(ctx, client, stored); err != nil {
		return s.connectionResult(time.Now(), false, stored.EncryptionMode, "SMTP_AUTHENTICATION_FAILED")
	}
	_ = client.Quit()
	return ConnectionTestResult{OK: true, Result: "success", EncryptionMode: stored.EncryptionMode}
}

func (s *Service) sendMail(ctx context.Context, stored StoredSettings, to, subject, textBody, htmlBody string) ConnectionTestResult {
	client, closeFn, category := s.smtpClient(ctx, stored)
	if category != "" {
		return s.connectionResult(time.Now(), false, stored.EncryptionMode, category)
	}
	defer closeFn()
	if err := s.authenticate(ctx, client, stored); err != nil {
		return s.connectionResult(time.Now(), false, stored.EncryptionMode, "SMTP_AUTHENTICATION_FAILED")
	}
	from := mail.Address{Name: stored.FromName, Address: stored.FromEmail}
	message := buildMessage(stored, to, from.String(), subject, textBody, htmlBody)
	if err := client.Mail(stored.FromEmail); err != nil {
		return s.connectionResult(time.Now(), false, stored.EncryptionMode, "SMTP_DELIVERY_FAILED")
	}
	if err := client.Rcpt(to); err != nil {
		return s.connectionResult(time.Now(), false, stored.EncryptionMode, "SMTP_RECIPIENT_REJECTED")
	}
	writer, err := client.Data()
	if err != nil {
		return s.connectionResult(time.Now(), false, stored.EncryptionMode, "SMTP_DELIVERY_FAILED")
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return s.connectionResult(time.Now(), false, stored.EncryptionMode, "SMTP_DELIVERY_FAILED")
	}
	if err := writer.Close(); err != nil {
		return s.connectionResult(time.Now(), false, stored.EncryptionMode, "SMTP_DELIVERY_FAILED")
	}
	_ = client.Quit()
	return ConnectionTestResult{OK: true, Result: "success", EncryptionMode: stored.EncryptionMode}
}

func buildMessage(stored StoredSettings, to, from, subject, textBody, htmlBody string) []byte {
	domain := "localhost"
	if address, err := mail.ParseAddress(stored.FromEmail); err == nil {
		if _, after, ok := strings.Cut(address.Address, "@"); ok && after != "" {
			domain = after
		}
	}
	messageID := randomMessageID(domain)
	headers := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Message-ID: " + messageID + "\r\n" +
		"MIME-Version: 1.0\r\n"
	if strings.TrimSpace(htmlBody) == "" {
		return []byte(headers + "Content-Type: text/plain; charset=UTF-8\r\n\r\n" + textBody + "\r\n")
	}
	boundary := "secureshare-" + randomHex(12)
	return []byte(headers +
		"Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n" +
		"--" + boundary + "\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + textBody + "\r\n" +
		"--" + boundary + "\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" + htmlBody + "\r\n" +
		"--" + boundary + "--\r\n")
}

func randomMessageID(domain string) string {
	return "<" + randomHex(16) + "@" + domain + ">"
}

func randomHex(bytes int) string {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func MaskAddress(address string) string {
	parsed, err := mail.ParseAddress(strings.TrimSpace(address))
	if err != nil {
		return ""
	}
	local, domain, ok := strings.Cut(parsed.Address, "@")
	if !ok || local == "" {
		return ""
	}
	first := local[:1]
	return first + "***@" + domain
}

func (s *Service) smtpClient(ctx context.Context, stored StoredSettings) (*smtp.Client, func(), string) {
	address := net.JoinHostPort(stored.SMTPHost, fmt.Sprintf("%d", stored.SMTPPort))
	timeout := time.Duration(stored.ConnectionTimeoutSeconds) * time.Second
	dialer := &net.Dialer{Timeout: timeout}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if stored.EncryptionMode == EncryptionTLS {
		conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: stored.SMTPHost})
		if err != nil {
			return nil, nil, smtpCategory(err, "SMTP_TLS_FAILED")
		}
		_ = conn.SetDeadline(deadline)
		client, err := smtp.NewClient(conn, stored.SMTPHost)
		if err != nil {
			_ = conn.Close()
			return nil, nil, "SMTP_TLS_FAILED"
		}
		return client, func() { _ = client.Close() }, ""
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, smtpCategory(err, "SMTP_CONNECTION_FAILED")
	}
	_ = conn.SetDeadline(deadline)
	client, err := smtp.NewClient(conn, stored.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return nil, nil, "SMTP_CONNECTION_FAILED"
	}
	if stored.EncryptionMode == EncryptionStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			_ = client.Close()
			return nil, nil, "SMTP_TLS_FAILED"
		}
		if err := client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: stored.SMTPHost}); err != nil {
			_ = client.Close()
			return nil, nil, "SMTP_TLS_FAILED"
		}
	}
	return client, func() { _ = client.Close() }, ""
}

func (s *Service) authenticate(ctx context.Context, client *smtp.Client, stored StoredSettings) error {
	if stored.SMTPUsername == "" && stored.SMTPPasswordCiphertext == "" {
		return nil
	}
	passwordBytes, err := s.vault.Decrypt(ctx, stored.SMTPPasswordCiphertext)
	if err != nil {
		return err
	}
	password := string(passwordBytes)
	defer func() {
		passwordBytes = nil
		password = ""
	}()
	return client.Auth(smtp.PlainAuth("", stored.SMTPUsername, password, stored.SMTPHost))
}

func smtpCategory(err error, fallback string) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "SMTP_TIMEOUT"
	}
	return fallback
}

func defaultStoredSettings() StoredSettings {
	now := time.Now().UTC()
	settings := Settings{
		ID:                       SingletonID,
		Enabled:                  false,
		EncryptionMode:           EncryptionStartTLS,
		ConnectionTimeoutSeconds: 5,
		SendTimeoutSeconds:       10,
		DefaultSubject:           DefaultSubject,
		DefaultMessage:           DefaultMessage,
		CreatedAt:                now,
		UpdatedAt:                now,
	}
	return StoredSettings{Settings: settings}
}

func normalizeSettings(settings *Settings) {
	if settings.ID == uuid.Nil {
		settings.ID = SingletonID
	}
	if settings.EncryptionMode == "" {
		settings.EncryptionMode = EncryptionStartTLS
	}
	if settings.ConnectionTimeoutSeconds == 0 {
		settings.ConnectionTimeoutSeconds = 5
	}
	if settings.SendTimeoutSeconds == 0 {
		settings.SendTimeoutSeconds = 10
	}
	if settings.DefaultSubject == "" {
		settings.DefaultSubject = DefaultSubject
	}
	if settings.DefaultMessage == "" {
		settings.DefaultMessage = DefaultMessage
	}
}

func safeSettings(stored StoredSettings) Settings {
	settings := stored.Settings
	normalizeSettings(&settings)
	settings.PasswordConfigured = stored.SMTPPasswordCiphertext != ""
	return settings
}
