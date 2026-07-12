import requests
import sys


def fetch_headers(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        sys.exit(1)

    return dict(response.headers), response.status_code, response.url


SECURITY_HEADERS_SET = {h.lower() for h in SECURITY_HEADERS}
INFO_LEAK_HEADERS_SET = {h.lower() for h in INFO_LEAK_HEADERS}


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


def main():
    if len(sys.argv) != 2:
        print("Usage: python header_analyzer.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    headers, status_code, final_url = fetch_headers(url)
    categorized = categorize_headers(headers)

    print(f"\nAnalyzed: {final_url}  (status: {status_code})\n" + "=" * 50)

    print("\n[Security Headers Present]")
    if categorized["security"]:
        for k, v in categorized["security"].items():
            print(f"  {k}: {v}")
    else:
        print("  None found")

    print("\n[Info-Leaking Headers]")
    if categorized["info_leak"]:
        for k, v in categorized["info_leak"].items():
            print(f"  {k}: {v}")
    else:
        print("  None found")

    print("\n[Other Headers]")
    for k, v in categorized["other"].items():
        print(f"  {k}: {v}")



if __name__ == "__main__":
    main()