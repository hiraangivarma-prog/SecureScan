import re
import uuid
from urllib.parse import urlparse

import requests

from models import Finding


TIMEOUT_SECONDS = 10
USER_AGENT = "SecureScan/1.0 (passive assessment)"


def validate_url(url: str) -> str:
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("URL hostname is missing.")

    return url


def fetch_target(url: str):
    validate_url(url)

    response = requests.get(
        url,
        timeout=TIMEOUT_SECONDS,
        allow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )
    return response


def finding(**kwargs):
    return Finding(id=str(uuid.uuid4())[:8], **kwargs).model_dump()


def analyze_headers(response):
    headers = {k.lower(): v for k, v in response.headers.items()}
    findings = []

    if response.url.startswith("https://") and "strict-transport-security" not in headers:
        findings.append(finding(
            title="Missing HSTS",
            category="Security Misconfiguration",
            severity="Medium",
            confidence="High",
            evidence="Strict-Transport-Security header was not present in the final HTTPS response.",
            description="The HTTPS response does not advertise an HSTS policy.",
            impact="Browsers are not instructed by this response to enforce HTTPS through HSTS.",
            recommendation="Configure an appropriate Strict-Transport-Security policy after confirming HTTPS is correctly deployed.",
        ))

    content_type = headers.get("content-type", "")
    if "text/html" in content_type and "content-security-policy" not in headers:
        findings.append(finding(
            title="Missing Content Security Policy",
            category="Security Misconfiguration",
            severity="Low",
            confidence="High",
            evidence="Content-Security-Policy header was not present in the HTML response.",
            description="The HTML response does not provide a Content Security Policy.",
            impact="The browser does not receive CSP restrictions from this response that could help limit some classes of content/script injection.",
            recommendation="Consider implementing a restrictive Content Security Policy appropriate to the application.",
        ))

    if "x-content-type-options" not in headers:
        findings.append(finding(
            title="Missing X-Content-Type-Options",
            category="Security Misconfiguration",
            severity="Low",
            confidence="High",
            evidence="X-Content-Type-Options header was not present.",
            description="The response does not explicitly instruct browsers to avoid MIME-type sniffing.",
            impact="Some browsers may have additional content-type interpretation behavior than intended.",
            recommendation='Consider sending "X-Content-Type-Options: nosniff" where appropriate.',
        ))

    if "referrer-policy" not in headers:
        findings.append(finding(
            title="Missing Referrer-Policy",
            category="Security Misconfiguration",
            severity="Informational",
            confidence="High",
            evidence="Referrer-Policy header was not present.",
            description="The response does not explicitly define a referrer policy.",
            impact="Referrer information may follow browser defaults rather than an application-defined policy.",
            recommendation="Consider defining an appropriate Referrer-Policy.",
        ))

    if "server" in headers:
        findings.append(finding(
            title="Server header information disclosure",
            category="Information Disclosure",
            severity="Informational",
            confidence="High",
            evidence=f"Server header exposed: {headers['server']}",
            description="The response exposes server implementation information.",
            impact="Technology information can assist reconnaissance.",
            recommendation="Minimize unnecessary server and version disclosure where practical.",
        ))

    if "x-powered-by" in headers:
        findings.append(finding(
            title="X-Powered-By information disclosure",
            category="Information Disclosure",
            severity="Informational",
            confidence="High",
            evidence=f"X-Powered-By header exposed: {headers['x-powered-by']}",
            description="The response exposes application technology information.",
            impact="Technology information can assist reconnaissance.",
            recommendation="Remove unnecessary X-Powered-By disclosure where appropriate.",
        ))

    return findings


def analyze_cookies(response):
    findings = []
    for cookie in response.cookies:
        name = cookie.name
        rest = {str(k).lower(): str(v) for k, v in cookie._rest.items()}
        likely_session = bool(re.search(r"(session|sess|auth|token|jwt)", name, re.I))
        if not likely_session:
            continue

        missing = []
        if not cookie.secure:
            missing.append("Secure")
        if "httponly" not in rest:
            missing.append("HttpOnly")
        if "samesite" not in rest:
            missing.append("SameSite")

        if missing:
            findings.append(finding(
                title="Session-like cookie missing security attributes",
                category="Session Management",
                severity="Medium",
                confidence="Medium",
                evidence=f"Cookie '{name}' is missing: {', '.join(missing)}.",
                description="A cookie that appears related to authentication or session state lacks one or more common security attributes.",
                impact="Missing cookie protections may increase exposure depending on application context and how the cookie is used.",
                recommendation="Configure appropriate Secure, HttpOnly, and SameSite attributes for authentication/session cookies.",
            ))
    return findings


def analyze_redirects(response):
    findings = []
    if response.history:
        chain = " → ".join([r.url for r in response.history] + [response.url])
        findings.append(finding(
            title="Redirect chain observed",
            category="Observation",
            severity="Informational",
            confidence="High",
            evidence=chain,
            description="The target responded with one or more redirects before the final response.",
            impact="Redirect behavior is recorded as evidence for review.",
            recommendation="Review redirect destinations and confirm they are intentional.",
        ))
    return findings


def scan(url: str):
    response = fetch_target(url)
    findings = []
    findings.extend(analyze_headers(response))
    findings.extend(analyze_cookies(response))
    findings.extend(analyze_redirects(response))

    counts = {s: 0 for s in ["Critical", "High", "Medium", "Low", "Informational"]}
    for item in findings:
        counts[item["severity"]] += 1

    return {
        "target": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "content_type": response.headers.get("Content-Type", ""),
        "server": response.headers.get("Server"),
        "https": response.url.startswith("https://"),
        "redirect_count": len(response.history),
        "summary": counts,
        "findings": findings,
    }
