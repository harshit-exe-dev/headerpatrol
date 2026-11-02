# headerpatrol

A tiny command-line tool that checks a website's security headers, cookie
flags and HTTPS setup, then grades it out of 100.

It started as a checklist I kept doing by hand during security audits:
fetch a site, squint at the response headers, write down what's missing.
This is that checklist, automated. No dependencies, just Node.

## Install

```bash
git clone https://github.com/harshit-exe-dev/headerpatrol.git
cd headerpatrol
npm link   # puts `headerpatrol` on your PATH
```

Needs Node 18 or newer (it uses the built-in `fetch`).

## Usage

```bash
headerpatrol example.com
headerpatrol https://example.com --json
headerpatrol https://example.com --timeout 5000
```

Example output:

```
headerpatrol: https://example.com

  [✓] HTTPS                        site is served over HTTPS
  [✓] Strict-Transport-Security    max-age=31536000
  [✗] Content-Security-Policy      missing. Nothing restricts where scripts...
  [!] Referrer-Policy              missing, full page URLs leak to third-party sites

Score: 73/100  Grade: B
```

Exit code is `2` when the grade is D or F, so it can gate a CI pipeline:

```bash
headerpatrol https://my-site.com || echo "headers need work"
```

## What it checks

- **HTTPS** — is the site on HTTPS, and does plain HTTP upgrade automatically
- **Strict-Transport-Security** — present, and with a sane `max-age`
- **Content-Security-Policy** — present, and not weakened by
  `unsafe-inline` / `unsafe-eval`
- **Clickjacking protection** — `X-Frame-Options` or CSP `frame-ancestors`
- **X-Content-Type-Options** — `nosniff`
- **Referrer-Policy** and **Permissions-Policy** — present
- **Cookie flags** — every `Set-Cookie` checked for `Secure`, `HttpOnly`,
  `SameSite`
- **Version disclosure** — `Server` / `X-Powered-By` banners that advertise
  exact versions
- **CORS** — wildcard origin, and the dangerous wildcard-plus-credentials
  combination

## Scoring

Starts at 100. A failed check costs 15, a warning costs 6, notes are free.
Grades: A+ ≥ 95, A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, F below that.

The weights are judgement calls, not science. Missing HSTS on a login page
matters more than a missing Referrer-Policy, and the score tries to reflect
that.

## Scope

This is a passive check of one URL's response headers. It is not a
vulnerability scanner: it doesn't log in, crawl, fuzz or test your app's
logic. Run it against sites you own or have permission to test.

## Tests

```bash
npm test
```

## License

MIT
