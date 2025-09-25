import pandas as pd
import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime, timedelta
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# ---------------- HELPERS ----------------
def extract_dates(text):
    """Extracts dates from a given text string based on predefined patterns."""
    DATE_PATTERNS = [
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s+\d{4}",
        r"\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\s+\d{4}",
        r"\b\d{4}-\d{2}-\d{2}\b",
        r"\b\d{1,2}/\d{1,2}/\d{4}\b",
        r"\b20\d{2}\b"
    ]
    now = datetime.now()
    dates = []
    for pattern in DATE_PATTERNS:
        matches = re.findall(pattern, text, flags=re.IGNORECASE)
        for date_str in matches:
            parsed_date = None
            for fmt in ("%b %d, %Y", "%d %b %Y", "%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y", "%Y"):
                try:
                    parsed_date = datetime.strptime(date_str, fmt)
                    break
                except ValueError:
                    continue
            if parsed_date:
                dates.append(parsed_date)
    return dates

def is_blog_page(soup, url):
    """
    Comprehensive blog detection using multiple indicators
    """
    score = 0
    indicators = []
    
    # 1. URL-based indicators
    url_lower = url.lower()
    url_patterns = ['blog', 'article', 'post', 'news', 'story', 'content', 'journal', 'magazine']
    if any(pattern in url_lower for pattern in url_patterns):
        score += 3
        indicators.append("url_pattern")
    
    # 2. HTML structure indicators
    # Look for article tags
    if soup.find_all('article'):
        score += 4
        indicators.append("article_tags")
    
    # Look for blog-specific classes/IDs
    blog_classes = ['post', 'entry', 'blog', 'article', 'story', 'content', 'news-item']
    for element in soup.find_all(['div', 'section'], class_=re.compile('|'.join(blog_classes), re.I)):
        score += 2
        indicators.append("blog_classes")
        break
    
    # 3. Content indicators
    text = soup.get_text().lower()
    
    # Blog-specific keywords
    blog_keywords = ['posted on', 'published on', 'by author', 'read more', 'continue reading', 
                    'comments', 'leave a comment', 'share this', 'subscribe', 'follow us']
    keyword_count = sum(1 for keyword in blog_keywords if keyword in text)
    if keyword_count > 0:
        score += min(keyword_count, 3)
        indicators.append("blog_keywords")
    
    # 4. Date patterns (more comprehensive)
    date_patterns = [
        r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}\b',
        r'\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}\b',
        r'\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b',
        r'\b\d{1,2}[-/]\d{1,2}[-/]\d{4}\b',
        r'\b(?:yesterday|today|this week|this month|last week|last month)\b'
    ]
    
    date_found = False
    for pattern in date_patterns:
        if re.search(pattern, text, re.I):
            date_found = True
            break
    
    if date_found:
        score += 2
        indicators.append("date_patterns")
    
    # 5. Multiple article indicators
    # Look for multiple article-like elements
    article_elements = soup.find_all(['article', 'div'], class_=re.compile(r'post|entry|article|story', re.I))
    if len(article_elements) > 1:
        score += 3
        indicators.append("multiple_articles")
    
    # 6. Navigation indicators
    nav_links = soup.find_all('a', href=True)
    nav_texts = [link.get_text().lower().strip() for link in nav_links]
    nav_indicators = ['blog', 'news', 'articles', 'stories', 'journal', 'magazine']
    if any(indicator in ' '.join(nav_texts) for indicator in nav_indicators):
        score += 2
        indicators.append("nav_indicators")
    
    # 7. Meta tags
    meta_article = soup.find('meta', property='og:type', content='article')
    if meta_article:
        score += 3
        indicators.append("meta_article")
    
    # Threshold for blog detection
    is_blog = score >= 4
    return is_blog, score, indicators

def has_recent_content(soup, url):
    """
    Check for recent content using multiple methods
    """
    # Method 1: Date extraction (existing)
    text = soup.get_text(" ", strip=True)
    dates = extract_dates(text)
    now = datetime.now()
    for d in dates:
        if d >= now - timedelta(days=60):
            return True, "date_found"
    
    # Method 2: Look for recent indicators in text
    recent_indicators = [
        r'\b(?:today|yesterday|this week|this month|last week|last month)\b',
        r'\b(?:just|recently|latest|new|updated)\b',
        r'\b(?:2024|2023)\b'  # Current year indicators
    ]
    
    for pattern in recent_indicators:
        if re.search(pattern, text, re.I):
            return True, "recent_indicators"
    
    # Method 3: Check for multiple articles (indicates active blog)
    article_elements = soup.find_all(['article', 'div'], class_=re.compile(r'post|entry|article|story', re.I))
    if len(article_elements) >= 3:  # Multiple articles suggest active blog
        return True, "multiple_articles"
    
    # Method 4: Check for pagination (indicates multiple pages of content)
    pagination_indicators = ['next', 'previous', 'page 2', 'older posts', 'newer posts']
    pagination_found = any(indicator in text.lower() for indicator in pagination_indicators)
    if pagination_found:
        return True, "pagination"
    
    return False, "no_recent_content"

def get_article_links(soup, base_url, limit=10):
    """
    Finds a limited number of article links on a page with expanded patterns.
    """
    links = []
    # Expanded patterns for blog/article content
    content_patterns = [
        "blog", "article", "post", "news", "story", "stories", "content", 
        "journal", "magazine", "press", "media", "updates", "insights",
        "resources", "guides", "tips", "tutorials", "reviews", "opinion",
        "editorial", "feature", "featured", "latest", "recent", "archive"
    ]
    
    for a in soup.find_all("a", href=True):
        href = a["href"]
        href_lower = href.lower()
        if any(pattern in href_lower for pattern in content_patterns):
            full_url = urljoin(base_url, href)
            if full_url not in links:
                links.append(full_url)
        if len(links) >= limit:
            break
    return links

def check_site(url):
    """
    Efficient site checking with smart URL prioritization
    """
    # Prioritized URL patterns - check most common first
    priority_paths = [
        "",  # root page
        "/blog", "/blogs", "/articles", "/news", "/stories",
        "/content", "/journal", "/press", "/media"
    ]
    
    # Secondary paths - only check if priority paths don't work
    secondary_paths = [
        "/updates", "/insights", "/resources", "/guides", "/tips",
        "/tutorials", "/reviews", "/opinion", "/editorial", "/features",
        "/featured", "/latest", "/recent", "/archive", "/posts"
    ]
    
    urls_to_check = []
    
    # Add priority paths (HTTPS first, then HTTP)
    for path in priority_paths:
        if path:
            urls_to_check.extend([
                f"https://{url}{path}",
                f"http://{url}{path}"
            ])
        else:
            urls_to_check.extend([
                f"https://{url}",
                f"http://{url}"
            ])
    
    best_score = 0
    best_indicators = []
    recent_found = False
    recent_reason = ""
    checked_count = 0
    max_checks = 8  # Limit to prevent hanging
    
    for u in urls_to_check:
        if checked_count >= max_checks:
            break
            
        try:
            resp = requests.get(u, timeout=6, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                checked_count += 1
                continue
            
            soup = BeautifulSoup(resp.text, "html.parser")
            checked_count += 1
            
            # Check if this page looks like a blog
            is_blog, score, indicators = is_blog_page(soup, u)
            
            if is_blog and score > best_score:
                best_score = score
                best_indicators = indicators
                
                # Check for recent content
                recent, reason = has_recent_content(soup, u)
                if recent:
                    recent_found = True
                    recent_reason = reason
                    break  # Found recent content, no need to check more URLs
                    
        except Exception as e:
            checked_count += 1
            continue
    
    # If no recent content found in priority paths, check secondary paths
    if not recent_found and best_score < 6:
        for path in secondary_paths[:4]:  # Only check first 4 secondary paths
            if checked_count >= max_checks:
                break
                
            try:
                u = f"https://{url}{path}"
                resp = requests.get(u, timeout=4, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code != 200:
                    checked_count += 1
                    continue
                
                soup = BeautifulSoup(resp.text, "html.parser")
                checked_count += 1
                
                is_blog, score, indicators = is_blog_page(soup, u)
                if is_blog and score > best_score:
                    best_score = score
                    best_indicators = indicators
                    
                    recent, reason = has_recent_content(soup, u)
                    if recent:
                        recent_found = True
                        recent_reason = reason
                        break
                        
            except Exception:
                checked_count += 1
                continue
    
    # Decision logic
    if recent_found:
        result = "Yes"
    elif best_score >= 6:  # High confidence it's a blog
        result = "Yes"  # Assume it's active even without recent dates
    else:
        result = "No"
    
    return url, result

# ---------------- MAIN ----------------
def main():
    """
    Main function to read an Excel file, check URLs, and save the results.
    """
    if len(sys.argv) < 2:
        print("Usage: python article_checker.py <excel_filename>")
        print("Example: python article_checker.py my_urls.xlsx")
        sys.exit(1)

    input_filename = sys.argv[1]
    
    try:
        df = pd.read_excel(input_filename)
    except FileNotFoundError:
        print(f"Error: The input Excel file '{input_filename}' was not found.")
        sys.exit(1)

    if "URL" not in df.columns:
        print("Error: The Excel file must contain a column named 'URL'.")
        sys.exit(1)

    results = []
    with ThreadPoolExecutor(max_workers=8) as executor:  # Reduced workers
        futures = {executor.submit(check_site, site): site for site in df["URL"]}
        for future in as_completed(futures):
            url, articles_found = future.result()
            print(f"Checked: {url} → Articles Found:{articles_found}")
            results.append({"URL": url, "Articles_Found": articles_found})

    # Convert results to a DataFrame for easy merging
    results_df = pd.DataFrame(results)
    
    # Merge the results back into the original DataFrame
    df = df.merge(results_df, on="URL", how="left")

    # Remove sites where articles are not found
    before_count = len(df)
    df = df[df["Articles_Found"].astype(str) == "Yes"].copy()
    removed = before_count - len(df)
    if removed > 0:
        print(f"Removed {removed} site(s) without recent articles.")

    # Save the filtered DataFrame back to the original file
    df.to_excel(input_filename, index=False)
    print(f"\n✅ Finished! The original file '{input_filename}' has been updated with only sites that have recent articles.")
    sys.exit(0)

if __name__ == "__main__":
    main()