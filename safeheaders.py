"""Passive, beginner-friendly checker for common HTTP security headers."""

from __future__ import annotations

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


HEADER_GUIDANCE = {
    "Strict-Transport-Security": (
        "The browser is instructed to use HTTPS for this site.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    ),
    "Content-Security-Policy": (
        "A CSP can limit which sources a page may load content from.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    ),
    "X-Content-Type-Options": (
        "The nosniff value tells the browser not to guess a file's MIME type.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    ),
    "Referrer-Policy": (
        "Controls how much page address information is sent with later requests.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    ),
    "Permissions-Policy": (
        "Helps limit a page's access to browser features.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    ),
}


def normalize_url(value: str) -> str:
    """Require an HTTP(S) URL and add HTTPS when no scheme is provided."""
    candidate = value if "://" in value else f"https://{value}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid URL, for example https://example.com")
    if parsed.username or parsed.password:
        raise ValueError("Do not include a username or password in the URL")
    return candidate


def inspect(url: str, timeout: float = 5.0) -> dict:
    """Make one ordinary GET request and summarize selected response headers."""
    request = Request(url, headers={"User-Agent": "SafeHeaders/1.0 (educational checker)"})
    try:
        with urlopen(request, timeout=timeout) as response:
            final_url = response.geturl()
            headers = response.headers
            status = response.status
    except HTTPError as error:
        # Error responses can still contain useful headers.
        final_url = error.geturl()
        headers = error.headers
        status = error.code
        error.close()

    checks = []
    for name, (explanation, reference) in HEADER_GUIDANCE.items():
        value = headers.get(name)
        checks.append(
            {
                "header": name,
                "present": value is not None,
                "value": value,
                "explanation": explanation,
                "reference": reference,
            }
        )

    exposed = [name for name in ("Server", "X-Powered-By") if headers.get(name)]
    return {
        "url": url,
        "final_url": final_url,
        "https": urlparse(final_url).scheme == "https",
        "status": status,
        "checks": checks,
        "exposed_technology_headers": {name: headers.get(name) for name in exposed},
        "note": "This checks a few indicators and is not a complete security audit.",
    }


def print_report(result: dict) -> None:
    found = sum(check["present"] for check in result["checks"])
    total = len(result["checks"])
    print("SafeHeaders — basic security header check")
    print(f"URL: {result['final_url']}")
    print(f"HTTP status: {result['status']}")
    print(f"HTTPS: {'yes' if result['https'] else 'no'}")
    print(f"\nSummary: {found} of {total} security headers found")
    for check in result["checks"]:
        label = "OK" if check["present"] else "NOTICE"
        print(f"\n[{label}] {check['header']}")
        if check["value"]:
            print(f"  Value: {check['value']}")
        else:
            print(f"  Not found. {check['explanation']}")
        print(f"  Learn more: {check['reference']}")
    if result["exposed_technology_headers"]:
        print("\nHeaders that may reveal technology details:")
        for name, value in result["exposed_technology_headers"].items():
            print(f"  {name}: {value}")
    print(f"\nNote: {result['note']}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Passively check common HTTP security headers on one web page."
    )
    parser.add_argument("url", help="URL of a website you are authorized to check")
    parser.add_argument("--json", action="store_true", help="Print the report as JSON")
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Request timeout in seconds (default: 5)",
    )
    args = parser.parse_args()

    try:
        url = normalize_url(args.url)
        if args.timeout <= 0:
            raise ValueError("Timeout must be greater than zero")
        result = inspect(url, args.timeout)
    except (ValueError, URLError, TimeoutError, OSError) as error:
        print(f"Could not complete the check: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_report(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
