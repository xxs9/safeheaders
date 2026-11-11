# SafeHeaders

SafeHeaders is a small educational Python command-line tool. It checks common HTTP security headers on one web page and explains what the results mean.

## Who is it for?

Beginners learning Python and web security who want to understand how browser security headers work.

## What it checks

- Whether the final page URL uses HTTPS.
- Whether these headers are present: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- Whether `Server` or `X-Powered-By` reveal technology details.
- A plain-language report with links to documentation.

This report is a learning aid, not a security grade or a complete security audit. Finding a header does not prove that its value is configured correctly.

## Requirements

- Python 3.10 or newer
- No third-party packages

## Run it

```bash
python safeheaders.py https://example.com
```

To get JSON output:

```bash
python safeheaders.py https://example.com --json
```

To change the request timeout (in seconds):

```bash
python safeheaders.py https://example.com --timeout 8
```

## Example output

```text
SafeHeaders — basic security header check
URL: https://example.com/
HTTP status: 200
HTTPS: yes

Summary: 3 of 5 security headers found

[OK] Strict-Transport-Security
  The browser is instructed to use HTTPS for this site.
[NOTICE] Content-Security-Policy
  Not found. A CSP can limit which sources a page may load content from.
```

## Safe and authorized use

Only check a website that you own or have permission to assess. SafeHeaders sends one ordinary HTTP GET request to the URL you provide. It does not crawl the site, scan ports, or attempt to exploit vulnerabilities. Make sure this kind of request is allowed by the site's policy.

## Learning roadmap

1. Add unit tests for different sets of response headers.
2. Save reports as JSON files.
3. Practice on a local test website that you control.
4. Learn how to review header values, not only whether a header exists.
5. Add a GitHub Actions workflow to run the tests automatically.

## References

- [MDN: Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [MDN: HTTP response headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## License

MIT. See [LICENSE](LICENSE).
