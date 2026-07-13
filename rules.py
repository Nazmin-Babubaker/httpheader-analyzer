"""Reference data for HTTP security header analysis."""

SECURITY_HEADERS_SET = {
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
}

INFO_LEAK_HEADERS_SET = {
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
}

# name -> (why it matters, severity if missing)
SECURITY_HEADER_INFO = {
    "strict-transport-security": (
        "Forces browsers to use HTTPS only, preventing downgrade/SSL-stripping attacks.",
        "High",
    ),
    "content-security-policy": (
        "Restricts what scripts/resources can load, mitigating XSS and data injection.",
        "High",
    ),
    "x-content-type-options": (
        "Prevents browsers from MIME-sniffing responses away from the declared Content-Type.",
        "Medium",
    ),
    "x-frame-options": (
        "Prevents the page from being embedded in an iframe, mitigating clickjacking.",
        "Medium",
    ),
    "referrer-policy": (
        "Controls how much referrer info is leaked to other sites when navigating away.",
        "Medium",
    ),
    "permissions-policy": (
        "Restricts access to browser features (camera, mic, geolocation, etc.).",
        "Low",
    ),
    "cross-origin-opener-policy": (
        "Isolates browsing context to prevent cross-origin attacks like Spectre.",
        "Medium",
    ),
    "cross-origin-resource-policy": (
        "Restricts which origins can embed this resource.",
        "Low",
    ),
    "cross-origin-embedder-policy": (
        "Ensures embedded resources explicitly opt in, enabling cross-origin isolation.",
        "Low",
    ),
}

MISSING_HEADER_PENALTY = {
    "High": 10,
    "Medium": 5,
    "Low": 1,
}
MISCONFIGURATION_PENALTY = 10

INFO_LEAK_PENALTY = 2

GRADE_THRESHOLDS = [
    (90, "A+"),
    (80, "A"),
    (70, "B"),
    (60, "C"),
    (50, "D"),
    (0, "F"),
]