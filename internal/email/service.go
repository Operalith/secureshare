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
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"secureshare/internal/config"
	"secureshare/internal/observability"
)

var smtpHostnamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

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
	result := UpdateResult{}
	password := req.SMTPPassword
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
	if err := s.validateStored(next, next.Enabled); err != nil {
		return UpdateResult{}, err
	}
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
	if enabled {
		if err := s.validateStored(current, true); err != nil {
			return Settings{}, err
		}
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
		return s.configurationResult(start, EncryptionStartTLS, s.validateStored(defaultStoredSettings(), true))
	}
	if err := s.validateStored(stored, true); err != nil {
		return s.configurationResult(start, stored.EncryptionMode, err)
	}
	result := s.connectAndAuthenticate(ctx, stored)
	result.DurationMS = durationMilliseconds(start, true)
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
		return s.configurationResult(start, EncryptionStartTLS, s.validateStored(defaultStoredSettings(), true))
	}
	if err := s.validateStored(stored, true); err != nil {
		return s.configurationResult(start, stored.EncryptionMode, err)
	}
	if _, err := mail.ParseAddress(strings.TrimSpace(to)); err != nil {
		return s.failedResult(start, stored.EncryptionMode, CategoryRecipientRejected, false)
	}
	result := s.sendMail(ctx, stored, strings.TrimSpace(to), "SecureShare SMTP test", "This is a safe SecureShare SMTP test message. It does not contain a secret or one-time link.", "")
	result.DurationMS = durationMilliseconds(start, true)
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
		return s.configurationResult(start, EncryptionStartTLS, s.validateStored(defaultStoredSettings(), true))
	}
	if err := s.validateStored(stored, true); err != nil || !stored.Enabled {
		if err == nil {
			err = &ValidationError{Cause: ErrInvalid, Fields: map[string]string{"enabled": "SMTP delivery must be enabled."}}
		}
		return s.configurationResult(start, stored.EncryptionMode, err)
	}
	to := strings.TrimSpace(req.To)
	if _, err := mail.ParseAddress(to); err != nil {
		return s.failedResult(start, stored.EncryptionMode, CategoryRecipientRejected, false)
	}
	result := s.sendMail(ctx, stored, to, req.Rendered.Subject, req.Rendered.Text, req.Rendered.HTML)
	result.DurationMS = durationMilliseconds(start, true)
	return result
}

func (s *Service) failedResult(start time.Time, mode, category string, attempted bool) ConnectionTestResult {
	return ConnectionTestResult{
		OK:             false,
		Result:         "failed",
		ErrorCategory:  category,
		Code:           category,
		Message:        smtpSafeMessage(category),
		EncryptionMode: mode,
		DurationMS:     durationMilliseconds(start, attempted),
	}
}

func (s *Service) configurationResult(start time.Time, mode string, err error) ConnectionTestResult {
	result := s.failedResult(start, mode, CategoryConfigurationError, false)
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		result.Fields = validationErr.Fields
	}
	return result
}

func (s *Service) validateStored(stored StoredSettings, requireComplete bool) error {
	settings := stored.Settings
	fields := make(map[string]string)
	cause := ErrInvalid
	if settings.EncryptionMode != EncryptionStartTLS && settings.EncryptionMode != EncryptionTLS && settings.EncryptionMode != EncryptionNone {
		fields["encryption_mode"] = "Select STARTTLS, TLS, or none."
	} else if s.cfg.AppEnv == "production" && settings.EncryptionMode == EncryptionNone {
		fields["encryption_mode"] = "Unencrypted SMTP is not allowed in production."
		cause = ErrForbidden
	}
	if requireComplete && settings.SMTPHost == "" {
		fields["smtp_host"] = "SMTP host is required."
	} else if settings.SMTPHost != "" && !validSMTPHost(settings.SMTPHost) {
		fields["smtp_host"] = "Enter a valid SMTP host name or IP address."
	}
	if requireComplete && settings.SMTPPort == 0 {
		fields["smtp_port"] = "SMTP port is required."
	} else if settings.SMTPPort < 0 || settings.SMTPPort > 65535 {
		fields["smtp_port"] = "SMTP port must be between 1 and 65535."
	}
	if requireComplete && settings.FromEmail == "" {
		fields["from_email"] = "A valid sender email is required."
	} else if settings.FromEmail != "" && !validEmailAddress(settings.FromEmail) {
		fields["from_email"] = "A valid sender email is required."
	}
	if settings.ReplyToEmail != "" && !validEmailAddress(settings.ReplyToEmail) {
		fields["reply_to_email"] = "Enter a valid reply-to email."
	}
	if settings.SMTPUsername == "" && stored.SMTPPasswordCiphertext != "" {
		fields["smtp_username"] = "SMTP username is required when a password is configured."
	}
	if len(settings.SMTPHost) > 255 {
		fields["smtp_host"] = "SMTP host must be 255 characters or fewer."
	}
	if len(settings.SMTPUsername) > 255 {
		fields["smtp_username"] = "SMTP username must be 255 characters or fewer."
	}
	if len(settings.FromName) > 255 {
		fields["from_name"] = "From name must be 255 characters or fewer."
	}
	if len(settings.FromEmail) > 255 {
		fields["from_email"] = "From email must be 255 characters or fewer."
	}
	if len(settings.ReplyToEmail) > 255 {
		fields["reply_to_email"] = "Reply-to email must be 255 characters or fewer."
	}
	if settings.ConnectionTimeoutSeconds <= 0 || settings.ConnectionTimeoutSeconds > 60 {
		fields["connection_timeout_seconds"] = "Connection timeout must be between 1 and 60 seconds."
	}
	if settings.SendTimeoutSeconds <= 0 || settings.SendTimeoutSeconds > 120 {
		fields["send_timeout_seconds"] = "Send timeout must be between 1 and 120 seconds."
	}
	if settings.DefaultSubject == "" || len(settings.DefaultSubject) > 255 {
		fields["default_subject"] = "Default subject is required and must be 255 characters or fewer."
	}
	if settings.DefaultMessage == "" || len(settings.DefaultMessage) > 10*1024 {
		fields["default_message"] = "Default message is required and must be 10240 characters or fewer."
	}
	if len(settings.FooterText) > 2*1024 {
		fields["footer_text"] = "Footer text must be 2048 characters or fewer."
	}
	if len(fields) > 0 {
		return &ValidationError{Cause: cause, Fields: fields}
	}
	return nil
}

func (s *Service) connectAndAuthenticate(ctx context.Context, stored StoredSettings) ConnectionTestResult {
	client, _, closeFn, category := s.smtpClient(ctx, stored)
	if category != "" {
		return s.failedResult(time.Now(), stored.EncryptionMode, category, true)
	}
	defer closeFn()
	if category := s.authenticate(ctx, client, stored); category != "" {
		return s.failedResult(time.Now(), stored.EncryptionMode, category, true)
	}
	_ = client.Quit()
	return ConnectionTestResult{OK: true, Result: "success", EncryptionMode: stored.EncryptionMode}
}

func (s *Service) sendMail(ctx context.Context, stored StoredSettings, to, subject, textBody, htmlBody string) ConnectionTestResult {
	client, conn, closeFn, category := s.smtpClient(ctx, stored)
	if category != "" {
		return s.failedResult(time.Now(), stored.EncryptionMode, category, true)
	}
	defer closeFn()
	if category := s.authenticate(ctx, client, stored); category != "" {
		return s.failedResult(time.Now(), stored.EncryptionMode, category, true)
	}
	_ = conn.SetDeadline(operationDeadline(ctx, time.Duration(stored.SendTimeoutSeconds)*time.Second))
	from := mail.Address{Name: stored.FromName, Address: stored.FromEmail}
	message := buildMessage(stored, to, from.String(), subject, textBody, htmlBody)
	if err := client.Mail(stored.FromEmail); err != nil {
		return s.failedResult(time.Now(), stored.EncryptionMode, smtpCategory(err, CategoryDeliveryFailed), true)
	}
	if err := client.Rcpt(to); err != nil {
		return s.failedResult(time.Now(), stored.EncryptionMode, smtpCategory(err, CategoryRecipientRejected), true)
	}
	writer, err := client.Data()
	if err != nil {
		return s.failedResult(time.Now(), stored.EncryptionMode, smtpCategory(err, CategoryDeliveryFailed), true)
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return s.failedResult(time.Now(), stored.EncryptionMode, smtpCategory(err, CategoryDeliveryFailed), true)
	}
	if err := writer.Close(); err != nil {
		return s.failedResult(time.Now(), stored.EncryptionMode, smtpCategory(err, CategoryDeliveryFailed), true)
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

func (s *Service) smtpClient(ctx context.Context, stored StoredSettings) (*smtp.Client, net.Conn, func(), string) {
	address := net.JoinHostPort(stored.SMTPHost, fmt.Sprintf("%d", stored.SMTPPort))
	timeout := time.Duration(stored.ConnectionTimeoutSeconds) * time.Second
	dialer := &net.Dialer{Timeout: timeout}
	deadline := operationDeadline(ctx, timeout)
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, nil, smtpCategory(err, CategoryConnectionFailed)
	}
	_ = conn.SetDeadline(deadline)
	if stored.EncryptionMode == EncryptionTLS {
		tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: stored.SMTPHost})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, nil, nil, smtpCategory(err, CategoryTLSFailed)
		}
		client, err := smtp.NewClient(tlsConn, stored.SMTPHost)
		if err != nil {
			_ = tlsConn.Close()
			return nil, nil, nil, smtpCategory(err, CategoryTLSFailed)
		}
		return client, tlsConn, func() { _ = client.Close() }, ""
	}
	client, err := smtp.NewClient(conn, stored.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, smtpCategory(err, CategoryConnectionFailed)
	}
	if stored.EncryptionMode == EncryptionStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			_ = client.Close()
			return nil, nil, nil, CategoryTLSFailed
		}
		if err := client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: stored.SMTPHost}); err != nil {
			_ = client.Close()
			return nil, nil, nil, smtpCategory(err, CategoryTLSFailed)
		}
	}
	return client, conn, func() { _ = client.Close() }, ""
}

func (s *Service) authenticate(ctx context.Context, client *smtp.Client, stored StoredSettings) string {
	if stored.SMTPUsername == "" && stored.SMTPPasswordCiphertext == "" {
		return ""
	}
	var passwordBytes []byte
	if stored.SMTPPasswordCiphertext != "" {
		var err error
		passwordBytes, err = s.vault.Decrypt(ctx, stored.SMTPPasswordCiphertext)
		if err != nil {
			return CategoryConfigurationError
		}
	}
	password := string(passwordBytes)
	defer func() {
		passwordBytes = nil
		password = ""
	}()
	if err := client.Auth(smtp.PlainAuth("", stored.SMTPUsername, password, stored.SMTPHost)); err != nil {
		return smtpCategory(err, CategoryAuthenticationFailed)
	}
	return ""
}

func smtpCategory(err error, fallback string) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return CategoryTimeout
	}
	return fallback
}

func durationMilliseconds(start time.Time, attempted bool) int64 {
	duration := time.Since(start).Milliseconds()
	if attempted && duration < 1 {
		return 1
	}
	return duration
}

func operationDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func smtpSafeMessage(category string) string {
	switch category {
	case CategoryConfigurationError:
		return "SMTP configuration is incomplete."
	case CategoryConnectionFailed:
		return "Could not connect to the SMTP server."
	case CategoryTLSFailed:
		return "Secure SMTP negotiation failed."
	case CategoryAuthenticationFailed:
		return "SMTP authentication failed."
	case CategoryRecipientRejected:
		return "The SMTP server rejected the recipient."
	case CategoryTimeout:
		return "The SMTP operation timed out."
	default:
		return "SMTP delivery failed."
	}
}

func validSMTPHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 253 || strings.Contains(host, "..") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if !smtpHostnamePattern.MatchString(host) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func validEmailAddress(value string) bool {
	address, err := mail.ParseAddress(value)
	return err == nil && strings.EqualFold(address.Address, strings.TrimSpace(value))
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
