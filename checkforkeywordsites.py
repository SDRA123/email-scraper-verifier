import argparse
import os
import re
import sys
import pandas as pd
from urllib.parse import urlparse

# Common false positive dampeners (platforms/tools)
EXCLUDE_HINTS = {
    "gitlab","github","figma","canva","linkedin","facebook","twitter","x.com","instagram","pinterest","tiktok",
    "docs.google","drive.google","calendar.google","mail.google","outlook.live","office.com","bing.com","yahoo.com"
}

def parse_kw_list(s: str):
    """Parse comma-separated keywords into a set."""
    if not s:
        return set()
    return {x.strip().lower() for x in s.split(",") if x.strip()}

def normalized_url_only(u: str) -> str:
    """Return a lowercase string of host + path (no query/fragment) for keyword checks."""
    try:
        if not u or str(u).lower() == "nan":
            return ""
        s = str(u).strip()
        if not re.match(r"^https?://", s, re.I):
            s = "https://" + s
        p = urlparse(s)
        host = (p.netloc or "").lower()
        path = (p.path or "").lower()
        return host + path
    except Exception:
        return str(u).lower()

def is_keyword_url(u: str, include=set(), exclude=set(), debug=False) -> bool:
    """Check if URL contains any of the specified keywords."""
    low = normalized_url_only(u)
    if not low:
        return False
    
    # Quick exclude gates (platforms/tools)
    if any(x in low for x in EXCLUDE_HINTS):
        return False

    # Keyword hit logic: require at least one include kw and none of the excludes
    hit_include = any(kw in low for kw in include) if include else True
    hit_exclude = any(kw in low for kw in exclude)

    if debug:
        reasons = []
        for kw in include:
            if kw in low:
                reasons.append(f"+{kw}")
                if len(reasons) >= 5:
                    break
        for kw in exclude:
            if kw in low:
                reasons.append(f"-{kw}")
        print(f"[debug] URL={u} -> include={hit_include} exclude={hit_exclude} reasons={','.join(reasons)}")
    
    return hit_include and not hit_exclude

def main():
    ap = argparse.ArgumentParser(description="Filter websites based on custom keywords from URL & Organic Traffic list")
    ap.add_argument("input_path", help="Path to input .xlsx or .csv with columns: URL, Organic Traffic")
    ap.add_argument("--csv", action="store_true", help="Also write CSV alongside the Excel output")
    ap.add_argument("--min-traffic", type=float, default=None, help="Minimum Organic Traffic to keep (optional)")
    ap.add_argument("--include", type=str, default="", help="Comma-separated keywords to include (required)")
    ap.add_argument("--exclude", type=str, default="", help="Comma-separated keywords to exclude")
    ap.add_argument("--debug", action="store_true", help="Print match reasons for each URL")
    args = ap.parse_args()

    if not os.path.exists(args.input_path):
        print(f"File not found: {args.input_path}")
        sys.exit(1)

    # Parse keywords
    include_keywords = parse_kw_list(args.include)
    exclude_keywords = parse_kw_list(args.exclude)
    
    if not include_keywords:
        print("Error: At least one include keyword is required. Use --include to specify keywords.")
        sys.exit(1)

    ext = os.path.splitext(args.input_path)[1].lower()
    if ext == ".xlsx":
        df = pd.read_excel(args.input_path)
    elif ext == ".csv":
        df = pd.read_csv(args.input_path)
    else:
        print("Input must be .xlsx or .csv")
        sys.exit(1)

    if "URL" not in df.columns or "Organic Traffic" not in df.columns:
        print("Input must contain columns: URL, Organic Traffic")
        sys.exit(1)

    # Apply filters
    mask = df["URL"].astype(str).apply(
        lambda u: is_keyword_url(u, include=include_keywords, exclude=exclude_keywords, debug=args.debug)
    )

    if args.min_traffic is not None:
        try:
            df["Organic Traffic"] = pd.to_numeric(df["Organic Traffic"], errors="coerce").fillna(0)
        except Exception:
            pass
        mask = mask & (df["Organic Traffic"] >= float(args.min_traffic))

    out_df = df[mask].copy()

    base, _ = os.path.splitext(args.input_path)
    out_xlsx = f"{base}_filtered.xlsx"
    out_df.to_excel(out_xlsx, index=False)
    print(f"Saved {len(out_df)} filtered URLs to {out_xlsx}")

    if args.csv:
        out_csv = f"{base}_filtered.csv"
        out_df.to_csv(out_csv, index=False)
        print(f"Also saved CSV to {out_csv}")

if __name__ == "__main__":
    main()

