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

    return dict(response.headers)


def main():
    if len(sys.argv) != 2:
        print("Usage: python header_analyzer.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    headers = fetch_headers(url)

    print(f"\nHeaders for {url}:\n" + "-" * 40)
    for key, value in headers.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()