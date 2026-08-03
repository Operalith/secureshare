# UI QA Checklist

Use safe, isolated data. Never capture real credentials, recipient addresses, SMTP passwords, API client secrets, raw one-time links, secret values, session tokens, email bodies, or Authorization headers in screenshots, traces, logs, or bug reports.

## Automated Gate

- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] `make lint`
- [ ] `make ui-time-test`
- [ ] `make ui-navigation-test`
- [ ] `make openapi-validate`
- [ ] `make smoke`
- [ ] `make integration-test`
- [ ] `make security-test`
- [ ] `make qa-test`
- [ ] `make ui-e2e`

`make ui-e2e` must use the isolated test project, remove disposable volumes, and leave development dashboard/audit data unchanged.

## Role Matrix

| Item/action | Admin | Developer | Viewer |
| --- | :---: | :---: | :---: |
| Dashboard | Yes | Yes | Yes |
| Create Secret | Yes | Yes | No |
| Secret Links/metadata | Yes | Yes | Yes |
| Revoke action | Yes | Yes | No |
| API Clients | Yes | No | No |
| Users | Yes | No | No |
| Email Settings | Yes | No | No |
| System Status | Yes | No | Yes |
| API Documentation | Yes | Yes | Yes |
| Help | Yes | Yes | Yes |
| Account and Logout | Yes | Yes | Yes |

- [ ] Every visible item matches the current backend permission policy.
- [ ] Direct forbidden page requests produce an authenticated 403 without adding unauthorized items.
- [ ] Direct forbidden state-changing requests remain rejected by the backend.
- [ ] Viewer pages have no Create or Revoke controls.

## Route and Active-State Matrix

| Route | Active item |
| --- | --- |
| `/admin` | `dashboard` |
| `/admin/secrets/new` | `create-secret` |
| `/admin/secrets` | `secret-links` |
| `/admin/secrets/{id}` | `secret-links` |
| `/admin/api-clients` | `api-clients` |
| `/admin/api-clients/{id}` | `api-clients` |
| `/admin/users` | `users` |
| `/admin/users/{id}` | `users` |
| `/admin/settings/email` | `email-settings` |
| `/admin/status` and `/admin/system` | `system-status` |
| `/docs` | `api-docs` |
| `/admin/help` | `help` |
| `/admin/account` | `account` |
| Authenticated 403, 404, safe 500 | none |

- [ ] Exactly one normal-page item has `aria-current="page"`.
- [ ] Detail pages preserve their parent item.
- [ ] Navigating after a 403 restores the correct active item.

## Navigation Consistency

- [ ] For one role, item IDs, labels, count, order, groups, and icons are identical across all allowed routes.
- [ ] Desktop and mobile use the same item IDs and DOM; no duplicate IDs exist.
- [ ] SMTP readiness, dependency health, failed queries, and validation errors do not change navigation.
- [ ] Email Settings remains visible to authorized admins when SMTP is disabled.
- [ ] Create Secret remains visible to authorized users when SMTP is disabled.
- [ ] Disabling Swagger removes only API Documentation.
- [ ] Public OpenAPI mode shows only its explicitly public navigation item and no authenticated identity controls.

## Desktop Viewports

Check 1280×720, 1366×768, 1440×900, 1920×1080, and 2560×1440.

- [ ] Sidebar remains 252px wide and full-height across routes.
- [ ] Branding and account footer remain visible; navigation scrolls independently if needed.
- [ ] Every allowed item can be scrolled into view and is not clipped.
- [ ] Workspace position and sidebar width do not jump between pages.
- [ ] Main content uses available width without exceeding its 1520px maximum.
- [ ] Tables stay inside responsive wrappers and the document has no horizontal overflow.
- [ ] Header title, environment badge, theme control, and user menu remain stable.

## Mobile and Tablet Viewports

Check 375×812, 390×844, and 768×1024.

- [ ] Drawer starts closed and the opener exposes `aria-controls` and correct `aria-expanded`.
- [ ] Opening focuses Close; Tab and Shift+Tab remain inside the drawer.
- [ ] Escape and backdrop close the drawer and return focus to the opener.
- [ ] Selecting a navigation item closes the drawer and updates the active state.
- [ ] Body scrolling is locked only while the drawer is open.
- [ ] Resizing to desktop and route navigation leave no invisible overlay.
- [ ] All expected items remain reachable without clipping.
- [ ] Segmented controls and tables cause no horizontal document overflow.
- [ ] Logout uses the one POST action and returns to `/login`.

## Error and Empty States

- [ ] Authenticated 403, 404, and safe 500 responses retain the permitted shell and no active item.
- [ ] Unauthenticated protected requests redirect to `/login`.
- [ ] Failed dashboard/list/dependency data does not remove shell controls.
- [ ] Empty lists remain readable and do not collapse the layout.

## Assets, Fonts, Console, and Network

- [ ] Local CSS, JavaScript, Swagger assets, and favicons return 200 after redirects.
- [ ] There are no external CSS, JavaScript, font, analytics, or unexpected network requests.
- [ ] Any bundled `.woff2` response uses `font/woff2`; if no font binaries are present, verify the documented system fallback stack.
- [ ] CSP produces no application violation; local Swagger styles use only the allowed hash.
- [ ] No unhandled JavaScript error or unexpected authenticated asset 401 occurs.
- [ ] Font/image/script/style requests have no 404 or failed request.
- [ ] Technical values remain LTR and Persian text remains readable when present.

## Accessibility

- [ ] Skip-to-content link reaches the visible `main` landmark.
- [ ] Navigation and header landmarks have accessible labels and logical heading order.
- [ ] Active state is indicated by `aria-current`, not color alone.
- [ ] Decorative icons are hidden from assistive technology.
- [ ] Keyboard focus indicators are visible in light and dark themes.
- [ ] Drawer focus trap, Escape, return focus, and logical tab order work.
- [ ] Reduced-motion preference suppresses nonessential transition duration.
- [ ] Text, focus, hover, disabled, badge, and active-state contrast is readable in both themes.

## Data Redaction and Artifacts

- [ ] Use only isolated `example.local` accounts and synthetic metadata.
- [ ] No real secret is entered during visual QA.
- [ ] Screenshots and traces are generated only on failure and remain Git-ignored.
- [ ] `git status --ignored` confirms auth state, reports, traces, screenshots, and `node_modules` are ignored.
- [ ] Application and proxy logs contain no secret values, SMTP passwords, API client secrets, session tokens, Authorization headers, raw one-time URLs, recipient addresses, or email bodies.
- [ ] Development data contains no `ui-e2e-fixture` or `Isolated QA navigation fixture` rows after the run.
