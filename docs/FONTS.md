# Fonts

SecureShare does not load fonts from a CDN or external origin.

The Persian public recipient experience uses the locally hosted `Vazirmatn-Variable.woff2` variable font for weights 100 through 900. It is the unmodified `Vazirmatn[wght].woff2` file from the official Vazirmatn `v33.003` release:

- Source: <https://github.com/rastikerdar/vazirmatn/tree/v33.003>
- Upstream file: `fonts/webfonts/Vazirmatn[wght].woff2`
- SHA-256: `4e3fa217d38fdafc1fea4414ceb58ca5e662cf0ab5fa735a8c8c20e8b42cad92`
- License: SIL Open Font License 1.1, copied in `web/static/fonts/OFL.txt`

The browser loads the font only from `/static/fonts/Vazirmatn-Variable.woff2`; CSP restricts fonts to `font-src 'self'`. English continues to use the native system UI stack. Persian body copy uses a 15px base size with 1.8 line-height, while its longer main recipient title uses 28–33.6px, weight 700, and 1.55 line-height. The English main title uses 28.8–36px with 1.15 line-height. Secondary recipient state headings use 22.4–28px.

Technical values such as usernames, API keys, URLs, IDs, JSON, and secret values deliberately bypass Vazirmatn. They remain on the monospace stack with `direction: ltr` and `unicode-bidi: isolate` so mixed RTL/LTR content cannot reorder them.
