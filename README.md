# HTTP Security Header Analyzer

A command-line tool that fetches a website's HTTP response headers, checks them against security best practices, and produces a graded report (0–100, A+ to F) highlighting missing headers, risky configurations, and information-leaking headers.

## What It Does

Given a URL, the tool:

1. **Fetches** the site's HTTP response headers (following redirects, spoofing a normal browser User-Agent).
2. **Categorizes** headers into three buckets:
   - **Security headers** — headers like `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, etc. that harden a site against common attacks.
   - **Info-leak headers** — headers like `Server` or `X-Powered-By` that reveal backend technology/version info to attackers.
   - **Other** — everything else (not scored).
3. **Checks for misconfigurations** in the security headers that are present but set to weak/incorrect values (e.g. a CSP that allows `unsafe-inline`, an HSTS header with `max-age=0`, an `X-Frame-Options` value that isn't `DENY`/`SAMEORIGIN`).
4. **Finds missing headers** — any recommended security header that isn't present at all, ranked by severity (High/Medium/Low).
5. **Scores and grades** the site by starting at 100 and subtracting penalties for each missing header (weighted by severity), each misconfiguration, and each info-leak header found.
6. **Prints a report** to the terminal showing the score/grade plus a breakdown of all four categories above.

## How It's Implemented

The project is split into two files to separate reference data from logic:

- **`rules.py`** — pure data/configuration:
  - `SECURITY_HEADERS_SET` — the set of security headers being checked for.
  - `INFO_LEAK_HEADERS_SET` — headers considered information disclosure risks.
  - `SECURITY_HEADER_INFO` — maps each security header to a human-readable explanation and a severity (`High`/`Medium`/`Low`) used if it's missing.
  - `MISSING_HEADER_PENALTY` / `MISCONFIGURATION_PENALTY` / `INFO_LEAK_PENALTY` — point deductions used in scoring.
  - `GRADE_THRESHOLDS` — score cutoffs mapped to letter grades (A+ down to F).

- **`analyze.py`** — the logic and CLI entry point:
  - `fetch_headers(url)` — issues the HTTP GET request (10s timeout, browser-like headers, follows redirects) and returns the raw headers, status code, and final resolved URL. Warns if the response looks like it came from a WAF/bot-block/challenge page (status 403/429/503 or an `x-waf-block` header) rather than the real site.
  - `categorize_headers(headers)` — sorts the raw headers into security / info-leak / other, matching case-insensitively against the sets in `rules.py`.
  - `check_risky_values(security_headers)` — inspects the *values* of present security headers for known-weak configurations (not just presence/absence).
  - `find_missing_headers(security_headers)` — diffs the present headers against the full recommended set, returning what's missing along with the reason and severity, sorted High → Low.
  - `calculate_score(missing, issues, info_leak_count)` — applies the penalty weights from `rules.py` to compute a final 0–100 score and corresponding letter grade.
  - `main()` — wires it all together: fetch → categorize → analyze → score → print formatted report.

This keeps all the "what counts as good/bad" knowledge in one editable file (`rules.py`), so the scoring rules can be tuned without touching the fetching/parsing/printing logic in `analyze.py`.

## Requirements

- Python 3.7+
- The `requests` library (see `requirements.txt`)

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python analyze.py <url>
```

The URL can be given with or without a scheme — `https://` is assumed if omitted.

### Examples

```bash
python analyze.py example.com
python analyze.py https://example.com
```

### Sample Output

```
Analyzed: https://example.com  (status: 200)
==================================================
SCORE: 65/100   GRADE: C
==================================================

[Security Headers Present]
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN

[Misconfigurations]
  None found

[Missing Security Headers]
  [High] content-security-policy: Restricts what scripts/resources can load, mitigating XSS and data injection.
  [High] strict-transport-security: Forces browsers to use HTTPS only, preventing downgrade/SSL-stripping attacks.
  [Medium] referrer-policy: Controls how much referrer info is leaked to other sites when navigating away.
  ...

[Info-Leaking Headers]
  server: nginx
```

## Notes / Limitations

- This is a static header check — it does not crawl the site, test multiple pages, or verify that a CSP actually blocks what it claims to block.
- A 403/429/503 response or an `x-waf-block` header triggers a warning, since the headers being analyzed may belong to a bot-protection/challenge page rather than the actual target site.
- Scoring weights and thresholds are opinionated defaults defined in `rules.py` and can be adjusted there.
