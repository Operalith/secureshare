package email

import (
	"context"
	"fmt"
	"html"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	TemplateSourceFallback    = "fallback"
	TemplateSourceGlobal      = "global_default"
	TemplateSourcePerDelivery = "per_delivery"
)

var placeholderPattern = regexp.MustCompile(`{{\s*([A-Za-z0-9_]+)\s*}}`)

var messagePlaceholders = map[string]bool{
	"secure_link":     true,
	"secret_title":    true,
	"recipient_name":  true,
	"recipient_email": true,
	"sender_name":     true,
	"expires_at":      true,
	"expires_in":      true,
	"product_name":    true,
	"support_email":   true,
}

var subjectPlaceholders = map[string]bool{
	"secret_title": true,
	"product_name": true,
	"sender_name":  true,
}

type TemplateOverride struct {
	Subject string `json:"subject"`
	Message string `json:"message"`
	Footer  string `json:"footer_text"`
}

type TemplateContext struct {
	SecureLink     string
	SecretTitle    string
	RecipientName  string
	RecipientEmail string
	SenderName     string
	ExpiresAt      time.Time
	ExpiresIn      string
	ProductName    string
	SupportEmail   string
}

type RenderedTemplate struct {
	Subject        string `json:"subject"`
	Text           string `json:"text"`
	HTML           string `json:"html"`
	TemplateSource string `json:"template_source"`
}

type PreviewRequest struct {
	Subject string `json:"subject"`
	Message string `json:"message"`
	Footer  string `json:"footer_text"`
}

func (s *Service) Render(ctx context.Context, override *TemplateOverride, templateCtx TemplateContext) (RenderedTemplate, error) {
	settings, err := s.SafeSettings(ctx)
	if err != nil {
		settings = safeSettings(defaultStoredSettings())
	}
	return Render(settings, override, templateCtx)
}

func (s *Service) Preview(ctx context.Context, req PreviewRequest) (RenderedTemplate, error) {
	settings, err := s.SafeSettings(ctx)
	if err != nil {
		settings = safeSettings(defaultStoredSettings())
	}
	override := &TemplateOverride{Subject: req.Subject, Message: req.Message, Footer: req.Footer}
	return Render(settings, override, fakePreviewContext())
}

func Render(settings Settings, override *TemplateOverride, templateCtx TemplateContext) (RenderedTemplate, error) {
	subject, message, footer, source := resolveTemplates(settings, override)
	if err := validateTemplateInput(subject, message, footer); err != nil {
		return RenderedTemplate{}, err
	}
	values := placeholderValues(templateCtx)
	renderedSubject, err := renderPlaceholders(subject, values, subjectPlaceholders)
	if err != nil {
		return RenderedTemplate{}, err
	}
	if len(renderedSubject) > 255 {
		return RenderedTemplate{}, fmt.Errorf("%w: subject is too long", ErrInvalid)
	}
	renderedMessage, err := renderPlaceholders(message, values, messagePlaceholders)
	if err != nil {
		return RenderedTemplate{}, err
	}
	if !templateContainsPlaceholder(message, "secure_link") {
		renderedMessage = strings.TrimRight(renderedMessage, "\r\n") + "\n\nOpen the secure secret using this one-time link:\n" + templateCtx.SecureLink
	}
	if strings.TrimSpace(footer) != "" {
		renderedFooter, err := renderPlaceholders(footer, values, messagePlaceholders)
		if err != nil {
			return RenderedTemplate{}, err
		}
		renderedMessage += "\n\n" + renderedFooter
	}
	return RenderedTemplate{
		Subject:        renderedSubject,
		Text:           renderedMessage,
		HTML:           textToHTML(renderedSubject, renderedMessage),
		TemplateSource: source,
	}, nil
}

func resolveTemplates(settings Settings, override *TemplateOverride) (subject, message, footer, source string) {
	source = TemplateSourceFallback
	subject = DefaultSubject
	message = DefaultMessage
	footer = ""
	if strings.TrimSpace(settings.DefaultSubject) != "" || strings.TrimSpace(settings.DefaultMessage) != "" || strings.TrimSpace(settings.FooterText) != "" {
		source = TemplateSourceGlobal
		if strings.TrimSpace(settings.DefaultSubject) != "" {
			subject = settings.DefaultSubject
		}
		if strings.TrimSpace(settings.DefaultMessage) != "" {
			message = settings.DefaultMessage
		}
		footer = settings.FooterText
	}
	if override != nil && (strings.TrimSpace(override.Subject) != "" || strings.TrimSpace(override.Message) != "" || strings.TrimSpace(override.Footer) != "") {
		source = TemplateSourcePerDelivery
		if strings.TrimSpace(override.Subject) != "" {
			subject = override.Subject
		}
		if strings.TrimSpace(override.Message) != "" {
			message = override.Message
		}
		footer = override.Footer
	}
	return subject, message, footer, source
}

func validateTemplateInput(subject, message, footer string) error {
	if len(subject) > 255 {
		return fmt.Errorf("%w: subject template is too long", ErrInvalid)
	}
	if len(message) > 10*1024 {
		return fmt.Errorf("%w: message template is too long", ErrInvalid)
	}
	if len(footer) > 2*1024 {
		return fmt.Errorf("%w: footer is too long", ErrInvalid)
	}
	for _, value := range []string{subject, message, footer} {
		if hasDisallowedControl(value) {
			return fmt.Errorf("%w: template contains disallowed control characters", ErrInvalid)
		}
	}
	return nil
}

func renderPlaceholders(template string, values map[string]string, allowed map[string]bool) (string, error) {
	if strings.Contains(template, "{{") || strings.Contains(template, "}}") {
		for _, match := range placeholderPattern.FindAllStringSubmatch(template, -1) {
			name := match[1]
			if !allowed[name] {
				return "", fmt.Errorf("%w: unsupported placeholder %s", ErrInvalid, name)
			}
		}
		stripped := placeholderPattern.ReplaceAllString(template, "")
		if strings.Contains(stripped, "{{") || strings.Contains(stripped, "}}") {
			return "", fmt.Errorf("%w: malformed placeholder", ErrInvalid)
		}
	}
	return placeholderPattern.ReplaceAllStringFunc(template, func(match string) string {
		parts := placeholderPattern.FindStringSubmatch(match)
		if len(parts) != 2 {
			return match
		}
		return values[parts[1]]
	}), nil
}

func templateContainsPlaceholder(template, name string) bool {
	for _, match := range placeholderPattern.FindAllStringSubmatch(template, -1) {
		if len(match) == 2 && match[1] == name {
			return true
		}
	}
	return false
}

func placeholderValues(ctx TemplateContext) map[string]string {
	recipientName := strings.TrimSpace(ctx.RecipientName)
	if recipientName == "" {
		recipientName = "there"
	}
	productName := strings.TrimSpace(ctx.ProductName)
	if productName == "" {
		productName = "SecureShare"
	}
	senderName := strings.TrimSpace(ctx.SenderName)
	if senderName == "" {
		senderName = productName
	}
	expiresAt := "the configured expiration time"
	if !ctx.ExpiresAt.IsZero() {
		expiresAt = ctx.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return map[string]string{
		"secure_link":     strings.TrimSpace(ctx.SecureLink),
		"secret_title":    strings.TrimSpace(ctx.SecretTitle),
		"recipient_name":  recipientName,
		"recipient_email": strings.TrimSpace(ctx.RecipientEmail),
		"sender_name":     senderName,
		"expires_at":      expiresAt,
		"expires_in":      strings.TrimSpace(ctx.ExpiresIn),
		"product_name":    productName,
		"support_email":   strings.TrimSpace(ctx.SupportEmail),
	}
}

func textToHTML(subject, text string) string {
	var builder strings.Builder
	builder.WriteString(`<!doctype html><html><body style="margin:0;padding:24px;background:#f6f8f7;color:#16211f;font-family:Arial,sans-serif;">`)
	builder.WriteString(`<main style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #dfe6e3;padding:24px;">`)
	builder.WriteString(`<h1 style="font-size:20px;line-height:1.3;margin:0 0 16px;">`)
	builder.WriteString(html.EscapeString(subject))
	builder.WriteString(`</h1>`)
	for _, paragraph := range splitParagraphs(text) {
		builder.WriteString(`<p style="font-size:15px;line-height:1.6;margin:0 0 14px;">`)
		lines := strings.Split(paragraph, "\n")
		for index, line := range lines {
			if index > 0 {
				builder.WriteString("<br>")
			}
			builder.WriteString(html.EscapeString(line))
		}
		builder.WriteString(`</p>`)
	}
	builder.WriteString(`<p style="font-size:13px;line-height:1.5;margin:18px 0 0;color:#64716d;">This email contains only a one-time link. The secret value is never included in email.</p>`)
	builder.WriteString(`</main></body></html>`)
	return builder.String()
}

func splitParagraphs(text string) []string {
	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	chunks := strings.Split(normalized, "\n\n")
	out := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		chunk = strings.Trim(chunk, "\n")
		if strings.TrimSpace(chunk) != "" {
			out = append(out, chunk)
		}
	}
	return out
}

func hasDisallowedControl(value string) bool {
	for _, r := range value {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return true
		}
	}
	return false
}

func fakePreviewContext() TemplateContext {
	return TemplateContext{
		SecureLink:     "https://example.local/s#preview-token-not-real",
		SecretTitle:    "Example access package",
		RecipientName:  "Recipient Name",
		RecipientEmail: "recipient@example.local",
		SenderName:     "SecureShare Admin",
		ExpiresAt:      time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC),
		ExpiresIn:      "24 hours",
		ProductName:    "SecureShare",
		SupportEmail:   "support@example.local",
	}
}

func AllowedPlaceholders() []string {
	values := make([]string, 0, len(messagePlaceholders))
	for key := range messagePlaceholders {
		values = append(values, "{{"+key+"}}")
	}
	sort.Strings(values)
	return values
}

func ValidateSupportEmail(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if _, err := mail.ParseAddress(value); err != nil {
		return fmt.Errorf("%w: invalid support email", ErrInvalid)
	}
	return nil
}
