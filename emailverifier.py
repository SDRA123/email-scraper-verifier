#!/usr/bin/env python3
"""
Email Verification Script
Verifies emails from uploaded Excel/CSV files with an Email/emails column.
Supports single or multiple emails (comma-separated) per row.

- Basic mode (fast, when --no-smtp): syntax + MX + light reputation scoring
- Advanced mode (SMTP): live RCPT TO checks with per-MX notes

Outputs: <input>_verified.xlsx with 3 columns:
  Email_Verification_Quality, Email_Verification_Status, Email_Verification_Notes
"""

import os
import sys
import random
import socket
import smtplib
import argparse
import threading
from typing import List, Dict, Tuple

import pandas as pd
import dns.resolver  # pip install dnspython

# --------------------------- Config ---------------------------

MAX_WORKERS = int(os.getenv("GP_MAX_WORKERS", "4"))
SMTP_TIMEOUT = int(os.getenv("GP_SMTP_TIMEOUT", "8"))
SMTP_HELO_DOMAIN = os.getenv("GP_SMTP_HELO_DOMAIN", "example.com")
SMTP_MAIL_FROM = os.getenv("GP_SMTP_MAIL_FROM", f"check@{SMTP_HELO_DOMAIN}")

DO_SMTP_VERIFY = True
DEBUG_MODE = False

# High-reputation consumer inbox domains → small score bump in no-SMTP mode
HIGH_REP_DOMAINS = {
    "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "rocketmail.com",
    "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com", "aol.com", "zoho.com"
}

# Optional: role/local-part downgrade (basic mode only)
ROLE_PREFIXES = {"info", "admin", "support", "sales", "contact", "hello"}


# --------------------------- Utils ---------------------------

def dprint(*a, **k):
    if DEBUG_MODE:
        print(*a, **k)

def normalize_email(raw: str) -> str:
    """Normalize email address."""
    if raw is None or (isinstance(raw, float) and pd.isna(raw)):
        return ""
    e = str(raw).strip().lower()
    # Remove common obfuscations
    e = (e.replace("[at]", "@").replace("(at)", "@").replace(" at ", "@")
           .replace("[dot]", ".").replace("(dot)", ".").replace(" dot ", "."))
    e = e.replace(" ", "")
    return e.strip(").,;:>]}")

def email_host(email: str) -> str:
    """Extract domain from email."""
    try:
        return email.split("@", 1)[1].lower()
    except Exception:
        return ""

def email_local(email: str) -> str:
    try:
        return email.split("@", 1)[0].lower()
    except Exception:
        return ""


# --------------------------- MX/SMTP (cached) ---------------------------

_mx_cache: Dict[str, Tuple[List[str], str]] = {}
_mx_lock = threading.Lock()
_smtp_cache: Dict[str, Tuple[int, str, str]] = {}
_smtp_lock = threading.Lock()

def resolve_mx(domain: str) -> Tuple[List[str], str]:
    """Resolve MX records for domain with caching."""
    with _mx_lock:
        if domain in _mx_cache:
            return _mx_cache[domain]
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=SMTP_TIMEOUT)
        hosts = [str(r.exchange).rstrip('.') for r in answers]
        res = (hosts, "mx_ok")
    except Exception as e:
        dprint("[dns] %s -> %s" % (domain, type(e).__name__))
        res = ([], "no_mx")
    with _mx_lock:
        _mx_cache[domain] = res
    return res

def smtp_check_address(mx_host: str, rcpt: str) -> Tuple[bool, str]:
    """Check if email address is valid via SMTP."""
    try:
        server = smtplib.SMTP(mx_host, 25, timeout=SMTP_TIMEOUT)
        server.set_debuglevel(0)
        code, _ = server.helo(SMTP_HELO_DOMAIN)
        if code >= 400:
            server.quit()
            return False, "helo_fail"
        code, _ = server.mail(SMTP_MAIL_FROM)
        if code >= 400:
            server.quit()
            return False, "mailfrom_fail"
        code, _ = server.rcpt(rcpt)
        accepted = int(code) in (250, 251)
        note = "rcpt_%s" % code
        try:
            server.quit()
        except Exception:
            pass
        return accepted, note
    except (socket.timeout, smtplib.SMTPServerDisconnected):
        return False, "timeout"
    except smtplib.SMTPConnectError:
        return False, "connect_fail"
    except smtplib.SMTPHeloError:
        return False, "helo_error"
    except smtplib.SMTPRecipientsRefused:
        return False, "rcpt_refused"
    except Exception:
        return False, "smtp_error"

def verify_email_smtp(email: str) -> Tuple[int, str, str]:
    """Verify email using SMTP with caching."""
    with _smtp_lock:
        if email in _smtp_cache:
            return _smtp_cache[email]
    
    domain = email_host(email)
    if not domain:
        res = (0, "invalid", "no_domain")
        with _smtp_lock:
            _smtp_cache[email] = res
        return res

    mx_hosts, mx_note = resolve_mx(domain)
    if not mx_hosts:
        res = (30, "no_mx", mx_note)
        with _smtp_lock:
            _smtp_cache[email] = res
        return res

    accepted_any = False
    note_parts = [mx_note]
    for mx in mx_hosts[:3]:
        ok, note = smtp_check_address(mx, email)
        note_parts.append("%s:%s" % (mx, note))
        if ok:
            accepted_any = True
            break

    catchall = False
    if accepted_any:
        probe_local = "catchall_probe_%d" % (random.randint(100000, 999999))
        probe_addr = "%s@%s" % (probe_local, domain)
        for mx in mx_hosts[:2]:
            ok2, note2 = smtp_check_address(mx, probe_addr)
            note_parts.append("probe:%s" % note2)
            if ok2:
                catchall = True
                break

    if accepted_any and not catchall:
        res = (90, "deliverable", "; ".join(note_parts[:6]))
    elif accepted_any and catchall:
        res = (75, "catchall_suspected", "; ".join(note_parts[:6]))
    else:
        rejected = any(("rcpt_550" in n) or ("rcpt_551" in n) for n in note_parts)
        if rejected:
            res = (40, "rejected", "; ".join(note_parts[:6]))
        else:
            # Common for Gmail/Outlook/Yahoo (anti-harvesting)
            res = (55, "unverifiable_provider_neutral", "; ".join(note_parts[:6]))

    with _smtp_lock:
        _smtp_cache[email] = res
    return res

def verify_email_simple(email: str) -> Tuple[int, str, str]:
    """
    Simple, fast checks without SMTP:
      - Format
      - MX presence
      - Light reputation bump for well-known inbox providers
    Never returns 'unverifiable' in this mode.
    """
    domain = email_host(email)
    if not domain:
        return (0, "invalid", "no_domain")

    if "@" not in email or "." not in domain:
        return (0, "invalid", "bad_format")

    try:
        mx_hosts, mx_note = resolve_mx(domain)
    except Exception as e:
        return (50, "mx_check_failed", "dns_error:%s" % type(e).__name__)

    if not mx_hosts:
        return (30, "no_mx", "no_mx_records")

    base_score = 70
    status = "domain_ok"

    if domain in HIGH_REP_DOMAINS:
        base_score = 80
        status = "domain_ok_highrep"

    # Optional small downgrade for role addresses
    # No penalty for role addresses
    local = email_local(email)
# Just ignore ROLE_PREFIXES

    return (base_score, status, "mx=%s" % ",".join(mx_hosts[:3]))


# --------------------------- Worker Functions ---------------------------

def process_email_batch(worker_id: int, emails: List[str]) -> Dict[str, Tuple[int, str, str]]:
    """Process a batch of emails for verification."""
    results: Dict[str, Tuple[int, str, str]] = {}
    for email in emails:
        if not email:
            continue

        email = normalize_email(email)
        if not email:
            continue

        print("[Worker %d] Verifying: %s" % (worker_id, email))

        if DO_SMTP_VERIFY:
            quality, status, notes = verify_email_smtp(email)
        else:
            quality, status, notes = verify_email_simple(email)

        results[email] = (quality, status, notes)
        # ASCII-only log line (no Unicode symbols)
        print("[Worker %d]  OK %s - %s (%s)" % (worker_id, email, status, quality))

    return results


# --------------------------- Main ---------------------------

def main():
    global DO_SMTP_VERIFY, DEBUG_MODE

    ap = argparse.ArgumentParser(description="Email Verification Script")
    ap.add_argument("input_path", help="Path to input .xlsx/.csv with Email/emails column")
    ap.add_argument("--no-smtp", action="store_true", help="Disable SMTP verification (faster)")
    ap.add_argument("--debug", action="store_true", help="Verbose debug prints")
    args = ap.parse_args()

    DO_SMTP_VERIFY = not args.no_smtp
    DEBUG_MODE = args.debug

    input_path = args.input_path
    if not os.path.exists(input_path):
        print("File not found: %s" % input_path)
        sys.exit(1)

    # Load
    try:
        if input_path.lower().endswith(".xlsx"):
            df = pd.read_excel(input_path, engine="openpyxl")
        else:
            df = pd.read_csv(input_path)
    except Exception:
        try:
            df = pd.read_excel(input_path)
        except Exception as e:
            print("Failed to read file: %s" % e)
            sys.exit(1)

    # Find email column (case-insensitive)
    email_col = None
    for col in df.columns:
        if str(col).lower() in ("email", "emails"):
            email_col = col
            break

    if not email_col:
        print("Error: No 'Email' or 'emails' column found in the file")
        sys.exit(1)

    print("Found email column: '%s'" % email_col)
    print("SMTP verification: %s" % ("Enabled" if DO_SMTP_VERIFY else "Disabled"))

    # Collect unique emails
    all_emails = set()
    for _, row in df.iterrows():
        cell = row.get(email_col, "")
        if pd.isna(cell) or not str(cell).strip():
            continue
        for e in str(cell).split(","):
            em = normalize_email(e)
            if em and "@" in em:
                all_emails.add(em)

    if not all_emails:
        print("No valid emails found in the file")
        sys.exit(1)

    print("Found %d unique emails to verify" % len(all_emails))

    # Chunk
    email_list = list(all_emails)
    workers = max(1, min(MAX_WORKERS, len(email_list)))
    chunks = [email_list[i::workers] for i in range(workers)]
    chunks = [c for c in chunks if c]

    # Parallel
    from concurrent.futures import ThreadPoolExecutor, as_completed
    all_results: Dict[str, Tuple[int, str, str]] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(process_email_batch, i + 1, chunk) for i, chunk in enumerate(chunks)]
        for fut in as_completed(futures):
            all_results.update(fut.result())

    # Add columns
    df["Email_Verification_Quality"] = ""
    df["Email_Verification_Status"] = ""
    df["Email_Verification_Notes"] = ""

    for idx, row in df.iterrows():
        cell = row.get(email_col, "")
        if pd.isna(cell) or not str(cell).strip():
            continue

        entries = [normalize_email(e) for e in str(cell).split(",")]
        qualities, statuses, notes = [], [], []

        for em in entries:
            if em and em in all_results:
                q, s, n = all_results[em]
                qualities.append(str(q))
                statuses.append(s)
                notes.append(n)
            else:
                qualities.append("0")
                statuses.append("not_processed")
                notes.append("missing_or_invalid")

        df.at[idx, "Email_Verification_Quality"] = "; ".join(qualities)
        df.at[idx, "Email_Verification_Status"] = "; ".join(statuses)
        df.at[idx, "Email_Verification_Notes"] = "; ".join(notes)

    # Save
    base, _ext = os.path.splitext(input_path)
    output_path = "%s_verified.xlsx" % base
    df.to_excel(output_path, index=False)

    print("")
    print("Verification complete.")
    print("Results saved to: %s" % output_path)

    # Summary
    deliverable_count = sum(1 for r in all_results.values() if r[1] == "deliverable")
    catchall_count    = sum(1 for r in all_results.values() if r[1] == "catchall_suspected")
    rejected_count    = sum(1 for r in all_results.values() if r[1] == "rejected")
    no_mx_count       = sum(1 for r in all_results.values() if r[1] == "no_mx")

    print("")
    print("Summary:")
    print("  Total emails processed: %d" % len(all_results))
    print("  Deliverable: %d" % deliverable_count)
    print("  Catch-all suspected: %d" % catchall_count)
    print("  Rejected: %d" % rejected_count)
    print("  No MX records: %d" % no_mx_count)


if __name__ == "__main__":
    main()