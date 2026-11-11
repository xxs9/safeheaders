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
        "Браузеру наказано використовувати HTTPS для цього сайту.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    ),
    "Content-Security-Policy": (
        "Політика CSP допомагає обмежити джерела вмісту сторінки.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    ),
    "X-Content-Type-Options": (
        "Значення nosniff забороняє браузеру вгадувати MIME-тип файлу.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    ),
    "Referrer-Policy": (
        "Керує тим, скільки інформації про адресу сторінки передається далі.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    ),
    "Permissions-Policy": (
        "Допомагає обмежувати доступ сторінки до можливостей браузера.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    ),
}


def normalize_url(value: str) -> str:
    """Require an explicit HTTP(S) URL and add HTTPS when no scheme is given."""
    candidate = value if "://" in value else f"https://{value}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Вкажи коректну адресу, наприклад https://example.com")
    if parsed.username or parsed.password:
        raise ValueError("Не додавай логін або пароль до адреси сайту")
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
        # Error responses still carry useful headers; do not hide them.
        final_url = error.geturl()
        headers = error.headers
        status = error.code

    checks = []
    for name, (explanation, reference) in HEADER_GUIDANCE.items():
        value = headers.get(name)
        checks.append({
            "header": name,
            "present": value is not None,
            "value": value,
            "explanation": explanation,
            "reference": reference,
        })

    exposed = [name for name in ("Server", "X-Powered-By") if headers.get(name)]
    return {
        "url": url,
        "final_url": final_url,
        "https": urlparse(final_url).scheme == "https",
        "status": status,
        "checks": checks,
        "exposed_technology_headers": {
            name: headers.get(name) for name in exposed
        },
        "note": "Навчальна перевірка окремих ознак; це не повний аудит безпеки.",
    }


def print_report(result: dict) -> None:
    found = sum(check["present"] for check in result["checks"])
    total = len(result["checks"])
    print("SafeHeaders — базова перевірка заголовків")
    print(f"Адреса: {result['final_url']}")
    print(f"HTTP статус: {result['status']}")
    print(f"HTTPS: {'так' if result['https'] else 'ні'}")
    print(f"\nПідсумок: {found} з {total} захисних заголовків знайдено")
    for check in result["checks"]:
        label = "OK" if check["present"] else "УВАГА"
        print(f"\n[{label}] {check['header']}")
        if check["value"]:
            print(f"  Значення: {check['value']}")
        else:
            print(f"  {check['explanation']}")
        print(f"  Документація: {check['reference']}")
    if result["exposed_technology_headers"]:
        print("\nЗаголовки, що можуть розкривати технології:")
        for name, value in result["exposed_technology_headers"].items():
            print(f"  {name}: {value}")
    print(f"\nПримітка: {result['note']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Пасивна перевірка HTTP-заголовків безпеки.")
    parser.add_argument("url", help="Адреса сайту, який ти маєш право перевіряти")
    parser.add_argument("--json", action="store_true", help="Вивести звіт у форматі JSON")
    parser.add_argument("--timeout", type=float, default=5.0, help="Тайм-аут запиту в секундах (за замовчуванням 5)")
    args = parser.parse_args()

    try:
        url = normalize_url(args.url)
        if args.timeout <= 0:
            raise ValueError("Тайм-аут має бути більшим за нуль")
        result = inspect(url, args.timeout)
    except (ValueError, URLError, TimeoutError, OSError) as error:
        print(f"Не вдалося виконати перевірку: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_report(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
