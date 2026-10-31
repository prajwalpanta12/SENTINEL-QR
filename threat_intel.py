"""
AI-Based QR Code Threat Analyzer
Module: threat_intel.py
Purpose: Threat Intelligence Layer querying abuse.ch URLhaus, Google Safe Browsing,
         VirusTotal v3, WHOIS Domain Age, and SSL certificate expiration.
"""

import base64
import os
import socket
import ssl
import time
from datetime import datetime
import requests

_INTEL_CACHE = {}
CACHE_TTL_SECONDS = 900  # 15 minutes


def query_urlhaus(url: str, auth_key: str = None, timeout: float = 3.0) -> dict:
    """Queries abuse.ch URLhaus. The API requires a (free) Auth-Key sent as an
    HTTP header; without one the feed is reported as not configured instead of
    issuing a request that cannot succeed."""
    key = (auth_key or os.environ.get("URLHAUS_AUTH_KEY", "")).strip()
    if not key:
        return {
            "source": "URLhaus (abuse.ch)",
            "is_malicious": False,
            "threat_level": "SKIPPED",
            "status": "No URLhaus Auth-Key Configured",
            "score_penalty": 0
        }
    api_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        response = requests.post(api_endpoint, data={"url": url.strip()},
                                 headers={"Auth-Key": key}, timeout=timeout)
        if response.status_code in (401, 403):
            return {
                "source": "URLhaus (abuse.ch)",
                "is_malicious": False,
                "threat_level": "OFFLINE",
                "status": f"URLhaus rejected the Auth-Key (HTTP {response.status_code})",
                "score_penalty": 0
            }
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok":
                return {
                    "source": "URLhaus (abuse.ch)",
                    "is_malicious": True,
                    "threat_level": "CRITICAL",
                    "threat_type": data.get("threat", "Malware / Phishing Distribution"),
                    "tags": data.get("tags", []),
                    "status": "CONFIRMED MALICIOUS (URLhaus Blacklisted)",
                    "score_penalty": 100
                }
            elif data.get("query_status") == "no_results":
                return {
                    "source": "URLhaus (abuse.ch)",
                    "is_malicious": False,
                    "threat_level": "CLEAN",
                    "status": "Clean in URLhaus Threat Feed",
                    "score_penalty": 0
                }
    except Exception:
        pass

    return {
        "source": "URLhaus (abuse.ch)",
        "is_malicious": False,
        "threat_level": "OFFLINE",
        "status": "URLhaus Live Query Skipped (Offline Mode)",
        "score_penalty": 0
    }


def query_google_safe_browsing(url: str, api_key: str, timeout: float = 3.0) -> dict:
    """Queries Google Safe Browsing Lookup API v4 if user has configured an API key."""
    if not api_key or not api_key.strip():
        return {
            "source": "Google Safe Browsing v4",
            "is_malicious": False,
            "status": "No Safe Browsing API Key Configured",
            "score_penalty": 0
        }

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key.strip()}"
    payload = {
        "client": {"clientId": "sentinel-qr-analyzer", "clientVersion": "2.4.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url.strip()}]
        }
    }

    try:
        resp = requests.post(endpoint, json=payload, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                threat_type = matches[0].get("threatType", "MALICIOUS")
                return {
                    "source": "Google Safe Browsing v4",
                    "is_malicious": True,
                    "threat_level": "CRITICAL",
                    "status": f"FLAGGED by Google Safe Browsing: {threat_type}",
                    "score_penalty": 100
                }
            else:
                return {
                    "source": "Google Safe Browsing v4",
                    "is_malicious": False,
                    "status": "Clean in Google Safe Browsing",
                    "score_penalty": 0
                }
    except Exception as e:
        return {
            "source": "Google Safe Browsing v4",
            "is_malicious": False,
            "status": f"Safe Browsing API check failed: {str(e)}",
            "score_penalty": 0
        }

    return {"source": "Google Safe Browsing v4", "is_malicious": False, "status": "Inconclusive", "score_penalty": 0}


def query_virustotal(url: str, api_key: str, timeout: float = 3.5) -> dict:
    """Queries VirusTotal API v3 multi-vendor intelligence."""
    if not api_key or not api_key.strip():
        return {
            "source": "VirusTotal v3",
            "is_malicious": False,
            "threat_level": "SKIPPED",
            "status": "No VT API Key Configured",
            "score_penalty": 0
        }

    try:
        url_id = base64.urlsafe_b64encode(url.strip().encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": api_key.strip()}

        resp = requests.get(endpoint, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            if malicious >= 3:
                return {
                    "source": "VirusTotal v3",
                    "is_malicious": True,
                    "threat_level": "CRITICAL",
                    "status": f"FLAGGED MALICIOUS ({malicious}/{total} security engines)",
                    "score_penalty": 100
                }
            elif malicious > 0 or suspicious > 0:
                return {
                    "source": "VirusTotal v3",
                    "is_malicious": False,
                    "threat_level": "SUSPICIOUS",
                    "status": f"FLAGGED SUSPICIOUS ({malicious + suspicious}/{total} engines)",
                    "score_penalty": 40
                }
            return {
                "source": "VirusTotal v3",
                "is_malicious": False,
                "threat_level": "CLEAN",
                "status": f"Clean (0/{total} engines flagged)",
                "score_penalty": 0
            }
    except Exception:
        pass

    return {"source": "VirusTotal v3", "is_malicious": False, "status": "VT Query Skipped", "score_penalty": 0}


def get_domain_whois_age(domain: str) -> dict:
    """Attempts fast WHOIS lookup for domain creation date and age in days."""
    host = domain.split(":")[0]
    # Skip raw IP addresses
    if any(c.isdigit() for c in host.replace(".", "")):
        parts = host.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return {"domain_age_days": None, "creation_date": "N/A (Raw IP Host)", "status": "Raw IP"}

    try:
        import whois
        w = whois.whois(host)
        cdate = w.creation_date
        if isinstance(cdate, list):
            cdate = cdate[0]
        if isinstance(cdate, datetime):
            age_days = (datetime.now() - cdate).days
            return {
                "domain_age_days": max(0, age_days),
                "creation_date": cdate.strftime("%Y-%m-%d"),
                "status": "Young Domain (< 30 days)" if age_days < 30 else "Established Domain"
            }
    except Exception:
        pass

    return {"domain_age_days": None, "creation_date": "Protected / Unavailable", "status": "WHOIS Masked"}


def check_ssl_expiry_days(domain: str, port: int = 443, timeout: float = 2.0) -> dict:
    """Connects via SSL and calculates remaining certificate validity in days."""
    host = domain.split(":")[0]
    try:
        context = ssl.create_default_context()
        context.timeout = timeout
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert.get("notAfter")
                if expiry_str:
                    exp_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp_date - datetime.utcnow()).days
                    return {
                        "ssl_valid": True,
                        "days_to_expiry": days_left,
                        "issuer": dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "Verified CA"),
                        "expiry_date": exp_date.strftime("%Y-%m-%d")
                    }
    except Exception as e:
        return {"ssl_valid": False, "days_to_expiry": 0, "issuer": "None / Handshake Failed", "error": str(e)}

    return {"ssl_valid": False, "days_to_expiry": 0, "issuer": "None"}


def _feed_state(feed: dict) -> str:
    """Classify one feed result as hit, suspicious, clean, unavailable, or not configured."""
    if not feed:
        return "not_configured"
    status = str(feed.get("status", ""))
    level = str(feed.get("threat_level", "")).upper()
    if feed.get("is_malicious"):
        return "hit"
    if ("API Key" in status) or ("not configured" in status.lower()):
        return "not_configured"
    if level == "OFFLINE":
        return "unavailable"
    if level == "SKIPPED":
        return "not_configured"
    if ("failed" in status.lower()) or ("inconclusive" in status.lower()) or ("skipped" in status.lower()):
        return "unavailable"
    if (level == "CLEAN") or status.lower().startswith("clean") or ("clean in" in status.lower()):
        return "clean"
    if (level == "SUSPICIOUS") or feed.get("score_penalty", 0) > 0:
        return "suspicious"
    return "unavailable"


def query_threat_intelligence(url: str, vt_api_key: str = None, gsb_api_key: str = None,
                              urlhaus_auth_key: str = None) -> dict:
    """Aggregates all threat intelligence sources with TTL caching."""
    now = time.time()
    uh_key = (urlhaus_auth_key or os.environ.get("URLHAUS_AUTH_KEY", "")).strip()
    cache_key = f"{url.strip()}::{vt_api_key or ''}::{gsb_api_key or ''}::{uh_key}"

    if cache_key in _INTEL_CACHE:
        ts, cached = _INTEL_CACHE[cache_key]
        if now - ts < CACHE_TTL_SECONDS:
            return cached

    urlhaus = query_urlhaus(url, uh_key)
    vt = query_virustotal(url, vt_api_key) if vt_api_key else None
    gsb = query_google_safe_browsing(url, gsb_api_key) if gsb_api_key else None

    # Determine highest threat severity and keep unavailable/not-configured
    # feeds separate from clean results.  A missing key or an outage must never
    # be presented as evidence that the URL is clean.
    is_blacklisted = False
    penalty = 0
    status_notes = []
    feed_states = {
        "URLhaus": _feed_state(urlhaus),
        "VirusTotal": _feed_state(vt),
        "Google Safe Browsing": _feed_state(gsb),
    }

    if urlhaus.get("is_malicious"):
        is_blacklisted = True
        penalty = 100
        status_notes.append("Flagged by URLhaus (abuse.ch)")

    if gsb and gsb.get("is_malicious"):
        is_blacklisted = True
        penalty = 100
        status_notes.append("Flagged by Google Safe Browsing")

    if vt and vt.get("is_malicious"):
        is_blacklisted = True
        penalty = 100
        status_notes.append(vt["status"])
    elif vt and vt.get("score_penalty", 0) > 0:
        penalty = max(penalty, vt["score_penalty"])
        status_notes.append(vt["status"])

    available = [name for name, state in feed_states.items()
                 if state in ("clean", "suspicious", "hit")]
    unavailable = [name for name, state in feed_states.items() if state == "unavailable"]
    not_configured = [name for name, state in feed_states.items() if state == "not_configured"]

    if status_notes:
        final_status = " | ".join(status_notes)
    elif available:
        final_status = "No threat matches in available feeds: " + ", ".join(available)
    else:
        final_status = "Threat intelligence unavailable; no feed could be queried"

    if unavailable:
        final_status += " | Unavailable: " + ", ".join(unavailable)
    if not_configured:
        final_status += " | Not configured: " + ", ".join(not_configured)

    if status_notes:
        status_class = "hit"
    elif not available:
        status_class = "unavailable"
    elif unavailable or not_configured:
        status_class = "partial"
    else:
        status_class = "clean"

    result = {
        "status": final_status,
        "status_class": status_class,
        "feeds_available": available,
        "feeds_unavailable": unavailable,
        "feeds_not_configured": not_configured,
        "is_blacklisted": is_blacklisted,
        "penalty_score": penalty,
        "source": "Public & Commercial Feeds",
        "urlhaus": urlhaus,
        "virustotal": vt,
        "google_safebrowsing": gsb
    }

    _INTEL_CACHE[cache_key] = (now, result)
    return result


def summarize_intel_status(intel: dict) -> dict:
    """Short label for the UI card. "No match" is shown only for feeds that were
    actually queried; an outage or a missing key is never presented as clean."""
    queried = intel.get("feeds_available", [])
    short = {"URLhaus": "URLhaus", "VirusTotal": "VT", "Google Safe Browsing": "GSB"}
    names = " + ".join(short.get(n, n) for n in queried)
    if intel.get("is_blacklisted"):
        return {"label": "Blacklisted", "detail": names or "feed hit", "tone": "r"}
    if intel.get("penalty_score", 0) > 0:
        return {"label": "Suspicious", "detail": names, "tone": "y"}
    if not queried:
        missing = intel.get("feeds_not_configured", [])
        detail = "no keys configured" if missing and not intel.get("feeds_unavailable") else "no feed reachable"
        return {"label": "Not checked", "detail": detail, "tone": "y"}
    if intel.get("feeds_unavailable") or intel.get("feeds_not_configured"):
        return {"label": "No match", "detail": f"{names} only", "tone": "y"}
    return {"label": "No match", "detail": names, "tone": "g"}
