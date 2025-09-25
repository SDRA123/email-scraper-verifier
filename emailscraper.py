#!/usr/bin/env python3
"""
Guest-post email scraper — TURBO edition
Fast-first: HTTP parsing (requests + lxml/bs4) ➜ optional Selenium fallback
MX + SMTP scoring with caching, parallel SMTP pool, and faster Chrome settings.

Why faster?
- Avoids browser for most sites: fetch HTML directly and parse (much faster than Selenium).
- Only opens Selenium when HTTP pass finds no decent candidates.
- Blocks images in Chrome, longer implicit waits removed, tight timeouts.
- Caches MX results per domain and SMTP verdicts per email.
- Optionally skip SMTP entirely (use --no-smtp) or run reduced follow depth.
- Adjustable concurrency via MAX_WORKERS env.

Usage:
  pip install requests lxml beautifulsoup4 pandas dnspython selenium webdriver-manager openpyxl
  python guest_post_email_scraper_turbo.py input.xlsx [--no-smtp] [--debug] [--fast-only]

Env:
  GP_MAX_WORKERS, GP_HTTP_TIMEOUT, GP_FOLLOW_LIMIT, GP_HEADLESS, GP_PAGE_LOAD_TIMEOUT, GP_SMTP_HELO_DOMAIN, GP_SMTP_MAIL_FROM
"""

import os, re, sys, time, html, math, random, socket, smtplib, argparse
import threading
from typing import List, Set, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import pandas as pd
import dns.resolver  # pip install dnspython

from bs4 import BeautifulSoup
from lxml import html as lxml_html

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager

# --------------------------- Config ---------------------------

MAX_WORKERS = int(os.getenv("GP_MAX_WORKERS", "6"))
FOLLOW_LIMIT = int(os.getenv("GP_FOLLOW_LIMIT", "3"))
HTTP_TIMEOUT = float(os.getenv("GP_HTTP_TIMEOUT", "8.0"))
PAGE_LOAD_TIMEOUT = int(os.getenv("GP_PAGE_LOAD_TIMEOUT", "18"))
IDLE_AFTER_BODY = float(os.getenv("GP_IDLE_AFTER_BODY", "1.2"))

SMTP_TIMEOUT = int(os.getenv("GP_SMTP_TIMEOUT", "8"))
SMTP_HELO_DOMAIN = "smtp.auroraphoton.com"
SMTP_MAIL_FROM = "probe@auroraphoton.com"
DO_SMTP_VERIFY = True
DEBUG_MODE = False
FAST_ONLY = False  # if True, never use Selenium

DISPOSABLE_HINTS = {
    "gmail.com","yahoo.com","outlook.com","hotmail.com",
    "aol.com","icloud.com","proton.me","protonmail.com","live.com","msn.com","yandex.com"
}

EDITORIAL_PREF_LOCALPARTS = [
    "submissions@","submission@","submit@","contributors@","contributor@","contribute@",
    "editor@","editors@","editorial@","letters@","opinion@","opeds@","opiniondesk@","desk@",
    "pitch@","pitches@","tips@","newsroom@","press@","media@","pr@","communications@",
    "guest@","guestpost@","guest-post@","write@","writers@","writing@","content@","blog@",
    "partners@","partnerships@","collab@","collabs@","outreach@",
    "advert@","ads@","advertising@","sponsored@","sponsorships@"
]

GUEST_KEY_PHRASES = [
    "write for us","guest post","guest posting","guest blogger","submit article","submit a post",
    "submission guidelines","editorial guidelines","become a contributor","contribute","pitch us",
    "send us your story","guest blogging guidelines","submit your writing","submit your blog",
    "guest writer","guest author"
]

LIKELY_GUEST_PATH_HINTS = [
    "write-for-us","writeforus","guest-post","guest-posts","guest","contribute","contributors",
    "submit","submission","submissions","editorial","guidelines","press","media","contact",
    "contact-us","contacts","about","about-us","team","staff","impressum","privacy"
]

EMAIL_REGEX_LOOSE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,24}\b", re.I)
CLEANUP_AT = re.compile(r"\s*(?:\[at\]|\(at\)|\sat\s)\s*", re.I)
CLEANUP_DOT = re.compile(r"\s*(?:\[dot\]|\(dot\)|\sdot\s)\s*", re.I)

# --------------------------- Utils ---------------------------

def dprint(*a, **k):
    if DEBUG_MODE:
        print(*a, **k)

def normalize_email(raw: str) -> str:
    e = html.unescape(raw or "").strip()
    e = re.sub(r"^mailto:", "", e, flags=re.I)
    e = CLEANUP_AT.sub("@", e)
    e = CLEANUP_DOT.sub(".", e)
    e = re.sub(r"\s+", "", e)
    return e.strip(").,;:>]}").lower()

def site_root(host_or_url: str) -> str:
    if not host_or_url:
        return ""
    netloc = urlparse(host_or_url if "://" in host_or_url else "http://" + host_or_url).netloc.lower()
    return netloc.lstrip("www.")

def email_host(email: str) -> str:
    try:
        return email.split("@",1)[1].lower()
    except Exception:
        return ""

def is_company_domain(email: str, site_host: str) -> bool:
    host = email_host(email)
    sroot = site_root(site_host)
    return host.endswith(sroot) if host and sroot else False

def is_freemail(email: str) -> bool:
    return email_host(email) in DISPOSABLE_HINTS

def classify_role(email: str) -> str:
    el = email.lower()
    for pref in EDITORIAL_PREF_LOCALPARTS:
        if el.startswith(pref):
            return pref.rstrip("@")
    for pref in EDITORIAL_PREF_LOCALPARTS:
        if pref.rstrip("@") in el.split("@")[0]:
            return pref.rstrip("@")
    local = el.split("@")[0]
    if any(k in local for k in ["info","hello","contact","support","team"]):
        return "general"
    return "unknown"

def normalize_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return u
    if not re.match(r"^https?://", u, re.I):
        return "https://" + u
    return u

def guest_phrase_score(text: str) -> int:
    t = (text or "").lower()
    return sum(2 for p in GUEST_KEY_PHRASES if p in t)

def rank_emails_for_guestposting(emails: List[str], site_host: str, page_context_score: int) -> List[Tuple[str,int,str]]:
    ranked = []
    for e in set(emails):
        role = classify_role(e)
        score = 0
        if is_company_domain(e, site_host):
            score += 100
        for weight, pref in enumerate(EDITORIAL_PREF_LOCALPARTS[::-1], start=1):
            if e.startswith(pref):
                score += 45 + weight
                break
        if role not in ("unknown","general"):
            score += 10
        if is_freemail(e):
            score += -5 if role not in ("unknown","general") else -40
        if role == "general":
            score += 5
        score += page_context_score
        ranked.append((e, score, role))
    ranked.sort(key=lambda x: (-x[1], x[0]))
    return ranked

# --------------------------- HTTP client ---------------------------

def make_http_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(total=2, backoff_factor=0.2, status_forcelist=[429, 500, 502, 503, 504])
    s.mount("http://", HTTPAdapter(max_retries=retries, pool_connections=64, pool_maxsize=64))
    s.mount("https://", HTTPAdapter(max_retries=retries, pool_connections=64, pool_maxsize=64))
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.8",
        "Cache-Control": "no-cache",
    })
    return s

def fetch_html_fast(session: requests.Session, url: str) -> Tuple[str, str]:
    url = normalize_url(url)
    try:
        r = session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
        if r.status_code >= 400 and url.startswith("https://"):
            url2 = "http://" + url[len("https://"):]
            r = session.get(url2, timeout=HTTP_TIMEOUT, allow_redirects=True)
            url = url2
        if "text/html" in r.headers.get("Content-Type",""):
            return r.text, url
    except Exception:
        pass
    return "", url

def extract_emails_from_text(text: str) -> Set[str]:
    if not text:
        return set()
    t = html.unescape(text)
    t = t.replace("[AT]","@").replace("[at]","@").replace("(at)","@").replace(" at ","@")
    t = t.replace("[DOT]",".").replace("[dot]",".").replace("(dot)",".").replace(" dot ",".")
    return set(m.lower() for m in EMAIL_REGEX_LOOSE.findall(t))

def parse_html_for_emails(html_text: str) -> Tuple[Set[str], int, List[str]]:
    emails: Set[str] = set()
    ctx_score = guest_phrase_score(html_text or "")
    links: List[str] = []
    if not html_text:
        return emails, ctx_score, links

    try:
        soup = BeautifulSoup(html_text, "html.parser")
        # mailto links
        for a in soup.select("a[href^='mailto:']"):
            emails.add(normalize_email(a.get("href","")))
        # footer + body text
        for node in soup.select("footer"):
            emails |= extract_emails_from_text(node.get_text(" ", strip=True))
        emails |= extract_emails_from_text(soup.get_text(" ", strip=True))

        # links for follow
        for a in soup.select("a[href]"):
            href = a.get("href")
            if not href:
                continue
            links.append(href)
    except Exception:
        # fall back to lxml text extraction (fast)
        try:
            root = lxml_html.fromstring(html_text)
            text = root.text_content()
            emails |= extract_emails_from_text(text)
            links = root.xpath("//a/@href")
        except Exception:
            pass

    return emails, ctx_score, links

def collect_candidate_links_fast(base_url: str, links: List[str]) -> List[str]:
    out = []
    base_host = site_root(base_url)
    for href in links:
        try:
            absu = urljoin(base_url, href)
            if site_root(absu) != base_host:
                continue
            low = absu.lower()
            if any(h in low for h in LIKELY_GUEST_PATH_HINTS):
                out.append(absu)
        except Exception:
            continue
        if len(out) >= FOLLOW_LIMIT:
            break
    return out

# --------------------------- MX/SMTP (cached) ---------------------------

_mx_cache: Dict[str, Tuple[List[str], str]] = {}
_mx_lock = threading.Lock()
_smtp_cache: Dict[str, Tuple[int,str,str]] = {}
_smtp_lock = threading.Lock()

def resolve_mx(domain: str) -> Tuple[List[str], str]:
    with _mx_lock:
        if domain in _mx_cache:
            return _mx_cache[domain]
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=SMTP_TIMEOUT)
        hosts = [str(r.exchange).rstrip('.') for r in answers]
        res = (hosts, "mx_ok")
    except Exception:
        res = ([], "no_mx")
    with _mx_lock:
        _mx_cache[domain] = res
    return res

def smtp_check_address(mx_host: str, rcpt: str) -> Tuple[bool, str]:
    try:
        server = smtplib.SMTP(mx_host, 25, timeout=SMTP_TIMEOUT)
        server.set_debuglevel(0)
        code, _ = server.helo(SMTP_HELO_DOMAIN)
        if code >= 400:
            server.quit(); return False, "helo_fail"
        code, _ = server.mail(SMTP_MAIL_FROM)
        if code >= 400:
            server.quit(); return False, "mailfrom_fail"
        code, _ = server.rcpt(rcpt)
        accepted = int(code) in (250, 251)
        note = f"rcpt_{code}"
        try: server.quit()
        except Exception: pass
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
    with _smtp_lock:
        if email in _smtp_cache:
            return _smtp_cache[email]
    domain = email_host(email)
    if not domain:
        res = (0, "unverifiable", "bad_domain")
        with _smtp_lock: _smtp_cache[email]=res
        return res

    mx_hosts, mx_note = resolve_mx(domain)
    if not mx_hosts:
        res = (30, "no-mx", mx_note)
        with _smtp_lock: _smtp_cache[email]=res
        return res

    accepted_any = False
    note_parts = [mx_note]
    for mx in mx_hosts[:3]:
        ok, note = smtp_check_address(mx, email)
        note_parts.append(f"{mx}:{note}")
        if ok:
            accepted_any = True
            break

    catchall = False
    if accepted_any:
        probe_local = "catchall_probe_" + str(random.randint(100000, 999999))
        probe_addr = f"{probe_local}@{domain}"
        for mx in mx_hosts[:2]:
            ok2, note2 = smtp_check_address(mx, probe_addr)
            note_parts.append(f"probe:{note2}")
            if ok2:
                catchall = True
                break

    if accepted_any and not catchall:
        res = (90, "deliverable", "; ".join(note_parts[:6]))
    elif accepted_any and catchall:
        res = (75, "catch-all suspected", "; ".join(note_parts[:6]))
    else:
        rejected = any("rcpt_550" in n or "rcpt_551" in n for n in note_parts)
        if rejected: res = (40, "rejected", "; ".join(note_parts[:6]))
        else:        res = (55, "unverifiable", "; ".join(note_parts[:6]))

    with _smtp_lock:
        _smtp_cache[email] = res
    return res

# --------------------------- Selenium (fallback only) ---------------------------

def build_driver(headless: bool = True) -> webdriver.Chrome:
    chrome_options = Options()
    if headless:
        chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1400,900")
    chrome_options.add_argument("--lang=en-US")
    chrome_options.add_argument("--disable-notifications")
    chrome_options.add_argument("--disable-background-networking")
    chrome_options.add_argument("--disable-features=MediaRouter,InterestFeedContentSuggestions")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_argument("--disable-gcm-driver")
    chrome_options.add_argument("--blink-settings=imagesEnabled=false")
    chrome_options.add_argument("--log-level=3")
    chrome_options.add_argument("--disable-logging")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-logging", "enable-automation"])
    chrome_options.add_experimental_option("useAutomationExtension", False)
    # Block images via prefs too
    chrome_options.add_experimental_option("prefs", {"profile.managed_default_content_settings.images": 2})
    chrome_options.page_load_strategy = "eager"

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    return driver

def try_accept_cookies(driver):
    try:
        for text in ["accept","agree","got it","allow","ok","i accept","i agree"]:
            btns = driver.find_elements(By.XPATH, f"//button[translate(normalize-space(.),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')[contains(.,'{text}')]]")
            if btns:
                btns[0].click(); time.sleep(0.3); return
    except Exception: pass

def safe_get(driver, url):
    try:
        driver.get(url)
    except (TimeoutException, WebDriverException):
        if url.startswith("https://"):
            try: driver.get("http://" + url[len("https://"):])
            except Exception: pass
    try:
        WebDriverWait(driver, 8).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
    except TimeoutException:
        pass
    time.sleep(IDLE_AFTER_BODY)
    try_accept_cookies(driver)

def extract_with_selenium(driver) -> Tuple[Set[str], int]:
    emails: Set[str] = set()
    try:
        cf_nodes = driver.find_elements(By.CSS_SELECTOR, "a.__cf_email__, span.__cf_email__")
        for n in cf_nodes:
            enc = n.get_attribute("data-cfemail") or ""
            if enc:
                try:
                    r = int(enc[:2], 16)
                    dec = "".join(chr(int(enc[i:i+2], 16) ^ r) for i in range(2, len(enc), 2))
                    if EMAIL_REGEX_LOOSE.search(dec): emails.add(dec.lower())
                except Exception:
                    pass
    except Exception: pass
    try:
        for a in driver.find_elements(By.CSS_SELECTOR, "a[href^='mailto:']"):
            emails.add(normalize_email(a.get_attribute("href") or ""))
    except Exception: pass
    try:
        footer = driver.find_element(By.TAG_NAME, "footer")
        if footer:
            emails |= extract_emails_from_text(footer.get_attribute("innerText") or "")
            for a in footer.find_elements(By.CSS_SELECTOR, "a[href^='mailto:']"):
                emails.add(normalize_email(a.get_attribute("href") or ""))
    except Exception: pass
    try:
        nodes = driver.find_elements(By.XPATH, "//*[contains(text(),'@')]")
        for n in nodes:
            emails |= extract_emails_from_text(n.text or "")
    except Exception: pass
    try:
        html_text = driver.page_source or ""
        emails |= extract_emails_from_text(html_text)
        ctx = guest_phrase_score(html_text)
    except Exception:
        ctx = 0
    return emails, ctx

# --------------------------- Core scrape per URL ---------------------------

def fast_scrape(session: requests.Session, url: str) -> Tuple[Set[str], int, str, List[str]]:
    html_text, final_url = fetch_html_fast(session, url)
    emails, ctx, links = parse_html_for_emails(html_text)
    return emails, ctx, final_url, links

def follow_and_extract_fast(session: requests.Session, base_url: str, links: List[str]) -> Tuple[Set[str], int]:
    emails: Set[str] = set()
    best_ctx = 0
    cands = collect_candidate_links_fast(base_url, links)
    for link in cands:
        text, _ = fetch_html_fast(session, link)
        e2, ctx2, _links2 = parse_html_for_emails(text)
        if e2: emails |= e2
        best_ctx = max(best_ctx, ctx2 + (2 if any(k in link.lower() for k in ["write","guest","submit","contribute"]) else 0))
    return emails, best_ctx

def scrape_emails_for_site(session: requests.Session, url: str, domain_hint: str) -> Tuple[List[str], str, bool]:
    """Returns (ranked_emails, notes, used_selenium)"""
    used_selenium = False
    emails, ctx, final_url, links = fast_scrape(session, url)
    e_follow, best_ctx = follow_and_extract_fast(session, final_url, links)
    ctx = max(ctx, best_ctx)
    emails |= e_follow

    host = domain_hint or final_url or url
    filtered = []
    for e in emails:
        if is_company_domain(e, host):
            filtered.append(e)
        elif is_freemail(e):
            role = classify_role(e)
            if role not in ("unknown","general"):
                filtered.append(e)
    if not filtered and emails:
        filtered = sorted(emails)

    if not filtered and not FAST_ONLY:
        # Fallback to Selenium only when HTTP path finds nothing
        used_selenium = True
        driver = build_driver(headless=(os.getenv("GP_HEADLESS","1")!="0"))
        try:
            safe_get(driver, normalize_url(url))
            e2, ctx2 = extract_with_selenium(driver)
            links2 = [a.get_attribute("href") or "" for a in driver.find_elements(By.CSS_SELECTOR,"a[href]")]
            cands = collect_candidate_links_fast(normalize_url(url), links2)
            for fl in cands:
                safe_get(driver, fl)
                e3, ctx3 = extract_with_selenium(driver)
                e2 |= e3
                ctx2 = max(ctx2, ctx3 + (2 if any(k in fl.lower() for k in ["write","guest","submit","contribute"]) else 0))
            emails = e2
            ctx = max(ctx, ctx2)
            # re-filter
            filtered = []
            for e in emails:
                if is_company_domain(e, host):
                    filtered.append(e)
                elif is_freemail(e):
                    role = classify_role(e)
                    if role not in ("unknown","general"):
                        filtered.append(e)
            if not filtered and emails:
                filtered = sorted(emails)
        finally:
            try: driver.quit()
            except Exception: pass

    ranked = rank_emails_for_guestposting(filtered, host, ctx)
    notes = f"ctx={ctx}; src={'selenium' if used_selenium else 'http'}"
    return [e for e,_,_ in ranked], notes, used_selenium

# --------------------------- Worker orchestration ---------------------------

def process_rows(worker_id: int, tasks: List[Tuple[int, Dict]]) -> Dict[int, Tuple[List[str], str, List[int], List[str], List[str]]]:
    results: Dict[int, Tuple[List[str], str, List[int], List[str], List[str]]] = {}
    session = make_http_session()
    for idx, row in tasks:
        url = str(row.get("URL","")).strip()
        domain = str(row.get("Domain","")).strip()
        print(f"[Worker {worker_id}] Scraping: {url if url else '(no url)'}")
        if not url or url.lower() == "nan":
            results[idx] = ([], "no-url", [], [], [])
            print(f"[Worker {worker_id}]  ➜ No URL supplied; skipping.")
            continue

        ranked_emails, notes, used_selenium = scrape_emails_for_site(session, url, domain_hint=domain or url)

        email_qualities, email_statuses, smtp_notes_list = [], [], []

        if ranked_emails:
            for e in ranked_emails:
                if DO_SMTP_VERIFY:
                    q, s, n = verify_email_smtp(e)
                    email_qualities.append(str(q))
                    email_statuses.append(s)
                    smtp_notes_list.append(n)
                    print(f"[Worker {worker_id}]  ✓ {e} • {s} ({q})")
                else:
                    email_qualities.append("70")
                    email_statuses.append("not-verified")
                    smtp_notes_list.append("smtp_off")
                    print(f"[Worker {worker_id}]  ✓ {e} • not-verified")
        else:
            print(f"[Worker {worker_id}]  ➜ No email found [{notes}]")

        results[idx] = (
            ranked_emails,
            notes,
            email_qualities,
            email_statuses,
            smtp_notes_list
        )
    return results


# --------------------------- Main ---------------------------

def main():
    global DO_SMTP_VERIFY, DEBUG_MODE, FAST_ONLY

    ap = argparse.ArgumentParser(description="Guest-post email scraper — TURBO (HTTP-first, Selenium-fallback)")
    ap.add_argument("input_path", help="Path to input .xlsx with URL and Organic Traffic")
    ap.add_argument("--no-smtp", action="store_true", help="Disable SMTP verification")
    ap.add_argument("--debug", action="store_true", help="Verbose debug prints")
    ap.add_argument("--fast-only", action="store_true", help="Never use Selenium (HTTP only)")
    args = ap.parse_args()

    DO_SMTP_VERIFY = not args.no_smtp
    DEBUG_MODE = args.debug
    FAST_ONLY = args.fast_only or (os.getenv("GP_FAST_ONLY","0") == "1")

    input_path = args.input_path
    if not os.path.exists(input_path):
        print(f"File not found: {input_path}"); sys.exit(1)

    try:
        df = pd.read_excel(input_path, engine="openpyxl")
    except Exception:
        df = pd.read_excel(input_path)

    required_cols = ["URL","Organic Traffic"]
    for c in required_cols:
        if c not in df.columns:
            print(f"Missing required column: {c}"); sys.exit(1)

    for c in ["Email","All Guest Emails","Email Notes","Email Quality","Email Status","SMTP Notes"]:
        if c not in df.columns: df[c] = ""

    tasks: List[Tuple[int, Dict]] = []
    for idx, row in df.iterrows():
        existing = row.get("Email","")
        if isinstance(existing, float) and math.isnan(existing): existing = ""
        if str(existing).strip():
            print(f"[{idx+1}/{len(df)}] Skipped (already has email): {existing}")
            continue
        tasks.append((idx, row.to_dict()))

    if not tasks:
        base,_ = os.path.splitext(input_path)
        out = f"{base}_with_emails.xlsx"
        df.to_excel(out, index=False)
        print(f"No empty Email cells. Saved: {out}")
        return

    chunks: List[List[Tuple[int, Dict]]] = [[] for _ in range(MAX_WORKERS)]
    for i, task in enumerate(tasks):
        chunks[i % MAX_WORKERS].append(task)

    merged: Dict[int, Tuple[List[str], str, int, str, str]] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = []
        for wid, chunk in enumerate(chunks, start=1):
            if not chunk: continue
            futs.append(ex.submit(process_rows, wid, chunk))
        for f in as_completed(futs):
            merged.update(f.result())

    updated = 0
    for idx, (emails_ranked, notes, qualities, statuses, smtp_notes_list) in merged.items():
        df.at[idx, "Email"] = emails_ranked[0] if emails_ranked else ""
        df.at[idx, "All Guest Emails"] = ", ".join(emails_ranked)
        df.at[idx, "Email Notes"] = notes
        df.at[idx, "Email Quality"] = "; ".join(qualities)
        df.at[idx, "Email Status"] = "; ".join(statuses)
        df.at[idx, "SMTP Notes"] = "; ".join(smtp_notes_list)
        updated += 1
        print(f"[{idx+1}/{len(df)}] Final: {emails_ranked if emails_ranked else '(none)'}")


    base,_ = os.path.splitext(input_path)
    out = f"{base}_with_emails.xlsx"
    df.to_excel(out, index=False)
    print(f"Updated {updated} rows. Saved: {out}")

if __name__ == "__main__":
    main()
