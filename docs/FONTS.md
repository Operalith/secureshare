# Fonts

SecureShare does not load fonts from a CDN or external origin.

The CSS stack is prepared for these open-source families when licensed local font files are added to `web/static/fonts/`:

- Inter for Latin UI text.
- Vazirmatn for Persian, Arabic, and mixed RTL/LTR UI text.
- JetBrains Mono for code, IDs, URLs, tokens, and secret values.

Current repository state: no binary font files are bundled. The app uses professional system fallbacks and documents the local font directory instead of committing placeholder or unverifiable font binaries.
