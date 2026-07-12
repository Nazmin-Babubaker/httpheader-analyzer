import requests
import sys
from rules import (
    SECURITY_HEADERS_SET,
    INFO_LEAK_HEADERS_SET,
    SECURITY_HEADER_INFO,
    MISSING_HEADER_PENALTY,
    MISCONFIGURATION_PENALTY,
    INFO_LEAK_PENALTY,
    GRADE_THRESHOLDS,
)

def fetch_headers(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        sys.exit(1)

    return dict(response.headers), response.status_code, response.url





def categorize_headers(headers: dict) -> dict:
    """Split headers into security, info-leak, and other buckets."""
    result = {
        "security": {},
        "info_leak": {},
        "other": {},
    }

    for key, value in headers.items():
        key_lower = key.lower()
        if key_lower in SECURITY_HEADERS_SET:
            result["security"][key] = value
        elif key_lower in INFO_LEAK_HEADERS_SET:
            result["info_leak"][key] = value
        else:
            result["other"][key] = value

    return result


def check_risky_values(security_headers: dict) -> list:
    issues = []
    normalized = {k.lower(): v for k, v in security_headers.items()}

    if "x-frame-options" in normalized:
        val = normalized["x-frame-options"].strip().upper()
        if val not in ("DENY", "SAMEORIGIN"):
            issues.append(
                f"X-Frame-Options has an unrecognized/weak value: '{val}' "
                "(expected DENY or SAMEORIGIN)."
            )

    if "strict-transport-security" in normalized:
        val = normalized["strict-transport-security"].lower()
        if "max-age=0" in val:
            issues.append("Strict-Transport-Security max-age is 0, effectively disabling HSTS.")
        elif "includesubdomains" not in val:
            issues.append(
                "Strict-Transport-Security is missing 'includeSubDomains', "
                "leaving subdomains unprotected."
            )

    if "content-security-policy" in normalized:
        val = normalized["content-security-policy"].lower()
        if "unsafe-inline" in val or "unsafe-eval" in val:
            issues.append(
                "Content-Security-Policy allows 'unsafe-inline' or 'unsafe-eval', "
                "significantly weakening XSS protection."
            )
        if "default-src *" in val or "default-src: *" in val:
            issues.append("Content-Security-Policy default-src is wildcard '*', allowing any origin.")

    if "x-content-type-options" in normalized:
        val = normalized["x-content-type-options"].strip().lower()
        if val != "nosniff":
            issues.append(f"X-Content-Type-Options has unexpected value: '{val}' (expected 'nosniff').")

    return issues


def find_missing_headers(security_headers: dict) -> list:
    present_lower = {k.lower() for k in security_headers}
    missing = []
    for key in SECURITY_HEADERS_SET:
        if key not in present_lower:
            reason, severity = SECURITY_HEADER_INFO.get(key, ("", "Low"))
            missing.append((key, reason, severity))
    order = {"High": 0, "Medium": 1, "Low": 2}
    missing.sort(key=lambda x: order.get(x[2], 3))
    return missing

def calculate_score(missing: list, issues: list, info_leak_count: int) -> tuple:
    """Compute a 0-100 score and letter grade from findings."""
    score = 100

    for _, _, severity in missing:
        score -= MISSING_HEADER_PENALTY.get(severity, 4)

    score -= len(issues) * MISCONFIGURATION_PENALTY
    score -= info_leak_count * INFO_LEAK_PENALTY

    score = max(0, min(100, score))  # clamp between 0 and 100

    grade = "F"
    for threshold, letter in GRADE_THRESHOLDS:
        if score >= threshold:
            grade = letter
            break

    return score, grade


def main():
    if len(sys.argv) != 2:
        print("Usage: python header_analyzer.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    headers, status_code, final_url = fetch_headers(url)
    categorized = categorize_headers(headers)

    issues = check_risky_values(categorized["security"])
    missing = find_missing_headers(categorized["security"])
    score, grade = calculate_score(missing, issues, len(categorized["info_leak"]))

    print(f"\nAnalyzed: {final_url}  (status: {status_code})")
    print("=" * 50)
    print(f"SCORE: {score}/100   GRADE: {grade}")
    print("=" * 50)

    print("\n[Security Headers Present]")
    if categorized["security"]:
        for k, v in categorized["security"].items():
            print(f"  {k}: {v}")
    else:
        print("  None found")

    print("\n[Misconfigurations]")
    if issues:
        for issue in issues:
            print(f"  ⚠ {issue}")
    else:
        print("  None found")

    print("\n[Missing Security Headers]")
    if missing:
        for key, reason, severity in missing:
            print(f"  [{severity}] {key}: {reason}")
    else:
        print("  None — all checked headers are present")

    print("\n[Info-Leaking Headers]")
    if categorized["info_leak"]:
        for k, v in categorized["info_leak"].items():
            print(f"  {k}: {v}")
    else:
        print("  None found")


if __name__ == "__main__":
    main()