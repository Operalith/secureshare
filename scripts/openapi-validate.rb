#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'psych'

ROOT = File.expand_path('..', __dir__)
SPEC_PATH = File.join(ROOT, 'docs', 'openapi.yaml')
INIT_PATH = File.join(ROOT, 'web', 'static', 'swagger-ui', 'swagger-init.js')
DOCS_TEMPLATE = File.join(ROOT, 'web', 'templates', 'docs.html')

spec = Psych.safe_load(File.read(SPEC_PATH), aliases: false)

def require_key!(object, key, label)
  raise "#{label} missing #{key}" unless object.is_a?(Hash) && object.key?(key)
end

raise 'openapi must be 3.1.0' unless spec['openapi'] == '3.1.0'
require_key!(spec, 'paths', 'spec')
require_key!(spec, 'components', 'spec')
require_key!(spec['components'], 'schemas', 'components')
require_key!(spec['components'], 'securitySchemes', 'components')

required_paths = %w[
  /api/v1/auth/login
  /api/v1/auth/logout
  /api/v1/me
  /api/v1/secret-links
  /api/v1/secret-links/{id}
  /api/v1/secret-links/{id}/revoke
  /api/v1/secret-links/prepare
  /api/v1/secret-links/consume
  /api/v1/secret-links/send-email
  /api/v1/dashboard
  /api/v1/settings/email
  /api/v1/settings/email/test-connection
  /api/v1/settings/email/send-test
  /api/v1/settings/email/template-preview
  /api/v1/settings/email/enable
  /api/v1/settings/email/disable
  /api/v1/users
  /api/v1/users/{id}
  /api/v1/users/{id}/reset-password
  /api/v1/users/{id}/disable
  /api/v1/users/{id}/enable
  /api/v1/api-clients
  /api/v1/api-clients/{id}
  /api/v1/api-clients/{id}/disable
  /api/v1/api-clients/{id}/enable
  /api/v1/api-clients/{id}/revoke
  /api/v1/api-clients/{id}/rotate-secret
  /api/v1/admin/cleanup
  /health/live
  /health/ready
  /metrics
]

required_paths.each do |path|
  raise "missing documented path #{path}" unless spec['paths'].key?(path)
end

required_schemas = %w[
  StructuredSecretPayload
  StructuredSecretField
  TextSecretPayload
  JSONSecretPayload
  DeliveryRequest
  EmailDeliveryRequest
  EmailTemplateOverride
  EmailDeliveryResult
  EmailSettings
  UpdateEmailSettingsRequest
  SMTPConnectionTestResult
  SendTestEmailRequest
  EmailErrorResponse
  CreateSecretRequest
  CreateSecretResponse
  SecretMetadata
  SecretListResponse
  Pagination
  ErrorResponse
  DashboardResponse
  CurrentUser
  APIClient
  CreateAPIClientRequest
  CreateAPIClientResponse
]

schemas = spec['components']['schemas']
required_schemas.each do |name|
  raise "missing schema #{name}" unless schemas.key?(name)
end

schemes = spec['components']['securitySchemes']
raise 'ApiClientAuth must be HTTP Basic' unless schemes.dig('ApiClientAuth', 'type') == 'http' && schemes.dig('ApiClientAuth', 'scheme') == 'basic'
raise 'LegacyAdminBearer must be bearer' unless schemes.dig('LegacyAdminBearer', 'scheme') == 'bearer'

payload = schemas.dig('CreateSecretRequest', 'properties', 'payload')
raise 'CreateSecretRequest.payload must use oneOf' unless payload && schemas.dig('SecretPayload', 'oneOf')

field_value = schemas.dig('StructuredSecretField', 'properties', 'value')
raise 'structured field values must be writeOnly' unless field_value && field_value['writeOnly'] == true

client_secret = schemas.dig('CreateAPIClientResponse', 'allOf', 1, 'properties', 'client_secret')
raise 'client_secret must be writeOnly' unless client_secret && client_secret['writeOnly'] == true

smtp_password = schemas.dig('UpdateEmailSettingsRequest', 'properties', 'smtp_password')
raise 'smtp_password must be writeOnly' unless smtp_password && smtp_password['writeOnly'] == true

delivery = schemas.dig('CreateSecretRequest', 'properties', 'delivery')
raise 'CreateSecretRequest must document delivery.email' unless delivery && schemas.dig('DeliveryRequest', 'properties', 'email')

scopes = schemas.dig('CreateAPIClientRequest', 'properties', 'scopes', 'items', 'enum')
raise 'email:send scope must be documented' unless scopes&.include?('email:send')

init = File.read(INIT_PATH)
raise 'Swagger UI must disable persisted authorization' unless init.include?('persistAuthorization: false')
raise 'Swagger UI must disable remote validator' unless init.include?('validatorUrl: null')
raise 'Swagger UI initializer must not use browser storage' if init.match?(/localStorage|sessionStorage|indexedDB/)

template = File.read(DOCS_TEMPLATE)
raise 'docs template must load local Swagger UI bundle' unless template.include?('/static/swagger-ui/swagger-ui-bundle.js')
raise 'docs template must not use CDN assets' if template.match?(%r{(?:src|href)=["']https?://|cdn})

forbidden_examples = %w[sk_live_ password123 real-secret production-secret]
raw = File.read(SPEC_PATH)
forbidden_examples.each do |value|
  raise "OpenAPI contains forbidden realistic secret example #{value}" if raw.include?(value)
end

puts 'OpenAPI validation passed.'
