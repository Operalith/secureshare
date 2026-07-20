package email

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRenderDefaultGlobalAndPerDeliveryTemplates(t *testing.T) {
	ctx := renderContext()
	fallback, err := Render(Settings{}, nil, ctx)
	if err != nil {
		t.Fatalf("fallback render: %v", err)
	}
	if fallback.TemplateSource != TemplateSourceFallback || !strings.Contains(fallback.Text, ctx.SecureLink) {
		t.Fatalf("fallback render did not use safe defaults: %#v", fallback)
	}

	globalSettings := Settings{DefaultSubject: "{{product_name}} secure package", DefaultMessage: "Hello {{recipient_name}},\n\nUse {{secure_link}}", FooterText: "Support: {{support_email}}"}
	global, err := Render(globalSettings, nil, ctx)
	if err != nil {
		t.Fatalf("global render: %v", err)
	}
	if global.TemplateSource != TemplateSourceGlobal || global.Subject != "SecureShare secure package" || !strings.Contains(global.Text, "Support: support@example.local") {
		t.Fatalf("global template not applied: %#v", global)
	}

	override := &TemplateOverride{Subject: "{{sender_name}} sent access", Message: "Custom body for {{secret_title}}"}
	perDelivery, err := Render(globalSettings, override, ctx)
	if err != nil {
		t.Fatalf("per-delivery render: %v", err)
	}
	if perDelivery.TemplateSource != TemplateSourcePerDelivery || !strings.Contains(perDelivery.Text, "Open the secure secret using this one-time link:") || !strings.Contains(perDelivery.Text, ctx.SecureLink) {
		t.Fatalf("per-delivery override did not append secure link: %#v", perDelivery)
	}
}

func TestRenderRejectsUnknownUnsafeAndMalformedPlaceholders(t *testing.T) {
	for name, override := range map[string]TemplateOverride{
		"unknown":      {Subject: "Subject", Message: "Use {{unknown}}"},
		"secret value": {Subject: "Subject", Message: "Password {{password}}"},
		"subject link": {Subject: "Link {{secure_link}}", Message: "Use {{secure_link}}"},
		"malformed":    {Subject: "Subject", Message: "Hello {{recipient_name"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Render(Settings{}, &override, renderContext()); err == nil {
				t.Fatal("expected placeholder validation error")
			}
		})
	}
}

func TestRenderEscapesHTMLAndScripts(t *testing.T) {
	override := &TemplateOverride{
		Subject: "Secure <script>alert(1)</script>",
		Message: "Hello <b>{{recipient_name}}</b>\n\n<script>alert('x')</script>\n\n{{secure_link}}",
	}
	rendered, err := Render(Settings{}, override, renderContext())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(rendered.HTML, "<script>") || strings.Contains(rendered.HTML, "<b>Recipient") {
		t.Fatalf("HTML preview executed user-controlled markup: %s", rendered.HTML)
	}
	if !strings.Contains(rendered.HTML, "&lt;script&gt;") || !strings.Contains(rendered.HTML, "&lt;b&gt;Recipient Name&lt;/b&gt;") {
		t.Fatalf("HTML preview did not escape user-controlled markup: %s", rendered.HTML)
	}
}

func TestRenderValidationLimitsAndRecipientFallback(t *testing.T) {
	longSubject := strings.Repeat("a", 256)
	if _, err := Render(Settings{}, &TemplateOverride{Subject: longSubject, Message: "Use {{secure_link}}"}, renderContext()); err == nil {
		t.Fatal("expected subject length validation error")
	}
	longMessage := strings.Repeat("a", 10*1024+1)
	if _, err := Render(Settings{}, &TemplateOverride{Subject: "Subject", Message: longMessage}, renderContext()); err == nil {
		t.Fatal("expected message length validation error")
	}
	ctx := renderContext()
	ctx.RecipientName = ""
	rendered, err := Render(Settings{}, nil, ctx)
	if err != nil {
		t.Fatalf("recipient fallback render: %v", err)
	}
	if strings.Contains(rendered.Text, "Hello ,") || !strings.Contains(rendered.Text, "Hello there,") {
		t.Fatalf("empty recipient name was not handled gracefully: %s", rendered.Text)
	}
}

func TestPreviewUsesFakeValuesAndCreatesNoSecret(t *testing.T) {
	store := NewMemoryStore()
	service := NewService(testConfig("development"), store, &testVault{}, nil, nil)
	rendered, err := service.Preview(context.Background(), PreviewRequest{
		Subject: "{{product_name}} preview",
		Message: "Hello {{recipient_name}},\n\nUse {{secure_link}}",
	})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if !strings.Contains(rendered.Text, "preview-token-not-real") || strings.Contains(rendered.Text, "canary-secret-value") {
		t.Fatalf("preview did not use fake values safely: %#v", rendered)
	}
	if _, err := store.GetSettings(context.Background()); err == nil {
		t.Fatal("preview should not create or persist settings or secrets")
	}
}

func renderContext() TemplateContext {
	return TemplateContext{
		SecureLink:     "https://example.local/s#fragment-token",
		SecretTitle:    "Merchant credentials",
		RecipientName:  "Recipient Name",
		RecipientEmail: "recipient@example.local",
		SenderName:     "SecureShare Admin",
		ExpiresAt:      time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC),
		ExpiresIn:      "24 hours",
		ProductName:    "SecureShare",
		SupportEmail:   "support@example.local",
	}
}
