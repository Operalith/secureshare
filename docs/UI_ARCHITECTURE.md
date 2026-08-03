# UI Architecture

## Scope

SecureShare uses server-rendered Go templates. There is no client-side application framework and no client-side navigation API. The backend resolves the authenticated identity, permissions, navigation visibility, stable ordering, and active item before rendering the page.

The recipient flow at `/s` and the login page are intentionally outside the authenticated application shell.

## Application Shell

Every protected page renders the same two template definitions from `web/templates/_shell.html`:

- `app-sidebar` contains branding, grouped product navigation, the account entry, and the mobile backdrop.
- `app-header` contains the mobile opener, page title, environment badge, theme control, user menu, and the single Logout form.

Each protected page supplies its page-specific `<main id="main-content">` only. Authenticated 403, 404, and safe 500 pages use the same shell and navigation model. The skip link targets `main-content` on every protected page.

## Navigation Source of Truth

`internal/http/navigation.go` is the only definition of product navigation. Each `NavigationItem` has:

- a stable `ID` used by templates and tests;
- a user-facing label, URL, and decorative icon name;
- a group and numeric order;
- required backend permissions;
- explicit exact or prefix match patterns;
- an explicit `Public` flag when an item may appear in public OpenAPI mode.

`navigationGroups` defines the stable Workspace, Access, Settings, and Resources order. Account is separated from product navigation and rendered in the sidebar footer.

Handlers do not construct page-specific menus. `authenticatedPageData` gets the session from the request, calls `buildNavigation`, and adds the resulting model to template data. In development, the resolver logs only item IDs and the active item ID; it does not log user identity, tokens, credentials, or secret metadata.

## Authorization and Filtering

Navigation visibility derives from the same permission names enforced by backend handlers. `buildNavigation` includes an item only when all its `RequiredPermissions` are present in the PostgreSQL-backed session.

Current role results are:

| Role | Navigation item IDs |
| --- | --- |
| admin | `dashboard`, `create-secret`, `secret-links`, `api-clients`, `users`, `email-settings`, `system-status`, `api-docs`, `help`, `account` |
| developer | `dashboard`, `create-secret`, `secret-links`, `api-docs`, `help`, `account` |
| viewer | `dashboard`, `secret-links`, `system-status`, `api-docs`, `help`, `account` |

The UI also uses permission checks for page actions such as Create and Revoke. These checks improve clarity but never replace handler/API authorization. Direct unauthorized page requests return an authenticated 403 shell; direct unauthorized API requests remain backend-rejected.

## Feature Availability

Feature filtering represents availability, not readiness:

- `api-docs` is hidden only when `SWAGGER_UI_ENABLED=false`.
- Email Settings remains visible to authorized admins when SMTP is disabled or unconfigured.
- Create Secret remains visible to authorized users when SMTP is disabled because link-only delivery remains available.
- PostgreSQL, Vault, cleanup, SMTP, validation, or page-data failures do not change navigation.

When `OPENAPI_PUBLIC=true`, `/docs` uses the same authoritative item definition but filters to items explicitly marked `Public`. Public docs do not render account, identity, CSRF, or Logout controls.

## Active-Route Matching

Route matching is explicit and deterministic:

- `=` patterns are exact matches and are evaluated first.
- `^` patterns are route-prefix matches and are evaluated second.
- No substring matching is used.

This makes `/admin/secrets/new` activate `create-secret`, while `/admin/secrets` and `/admin/secrets/{id}` activate `secret-links`. Detail routes for API clients and users keep their list parent active. `/admin/system` and `/admin/status` both activate `system-status`. Normal protected pages have exactly one active item and render `aria-current="page"`; error and forbidden pages intentionally have none.

## Desktop and Mobile Rendering

Desktop and mobile use one navigation DOM and one server-generated item list. CSS turns the 252px full-height desktop sidebar into an off-canvas drawer at 820px and below. The navigation area scrolls independently while branding and account identity stay stable.

`web/static/admin.js` provides mobile-only interaction behavior:

- accessible open and close controls;
- Escape and backdrop close;
- close after selecting a link;
- focus trap while open and focus return to the opener;
- body scroll lock;
- safe reset on desktop resize and `pagehide`.

The script does not fetch or reconstruct menu items.

## Logout

There is one Logout form, in the authenticated user menu. It sends `POST /logout` with the session-bound CSRF token. The backend validates CSRF, revokes the PostgreSQL session, clears the browser cookie, and redirects to `/login`.

## Adding a Navigation Item Safely

1. Add the backend permission to the appropriate role policy in `internal/auth/users.go` and enforce it in the route handler/API.
2. Add exactly one `NavigationItem` in `internal/http/navigation.go` with a stable ID, group, order, permissions, and explicit match patterns.
3. Add feature filtering only if configuration can make the feature unavailable. Do not filter on dependency health or setup readiness.
4. Add or update page-action permission checks without treating them as authorization.
5. Add role, ordering, active-route, direct-access, shell, and browser assertions.
6. Update `docs/UI_QA_CHECKLIST.md` when the role or route matrix changes.
7. Run `go test ./...`, `make ui-navigation-test`, and `make ui-e2e`.

Do not add full navigation markup to a page template or create a separately hardcoded mobile menu.

## Regression Coverage

Go tests validate model filtering, ordering, exact active routes, dependency and validation stability, authenticated error shells, feature availability, and action visibility. The fast Node interaction test validates drawer state and keyboard behavior without a browser.

`make ui-e2e` runs pinned Playwright tests against disposable PostgreSQL, Vault, Mailpit, and app containers. It creates safe admin/developer/viewer fixtures, monitors console/CSP/network failures, checks responsive geometry, and removes containers, volumes, and temporary auth state after the run. Failure screenshots and traces remain Git-ignored under `artifacts/ui-e2e` for local diagnosis only.
