from flask import Flask, request, Response, stream_with_context
from flask_cors import CORS
import requests
import re
import json
import time
import random
from bs4 import BeautifulSoup, Comment
from typing import List, Dict, Optional

app = Flask(__name__)
CORS(app)

CDX_API = "https://web.archive.org/cdx/search/cdx"
TIMEOUT = 60
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Referer": "https://web.archive.org/"
}


def fetch_snapshots(domain: str, year: Optional[str] = None, limit: int = 100) -> List[Dict[str, str]]:
    """Fetch snapshots from Wayback Machine CDX API"""
    params = {
        "url": domain,
        "output": "json",
        "fl": "timestamp,original",
        "filter": "statuscode:200",
        "limit": str(limit)
    }
    
    if year:
        params["from"] = f"{year}0101"
        params["to"] = f"{year}1231"
    
    try:
        response = requests.get(CDX_API, params=params, headers=HEADERS, timeout=TIMEOUT)
        
        if response.status_code != 200:
            print(f"[Wayback] CDX API returned {response.status_code}")
            return []
        
        data = response.json()
        
        if not isinstance(data, list) or len(data) <= 1:
            return []
        
        # Skip header row and map to snapshot objects
        snapshots = []
        for row in data[1:]:
            if len(row) >= 2:
                snapshots.append({
                    "timestamp": row[0],
                    "original": row[1]
                })
        
        return snapshots
    
    except Exception as e:
        print(f"[Wayback] CDX API Error: {e}")
        return []


def extract_data(html: str, keyword: str, timestamp: str, archive_url: str) -> List[Dict]:
    """Extract keyword matches from HTML (text, JS, comments)"""
    matches = []
    soup = BeautifulSoup(html, 'lxml')
    
    # 1. CLEANUP: Remove Wayback Machine's injected Toolbar & Scripts
    for element in soup.select("#wm-ipp-base, #wm-ipp, #donato"):
        element.decompose()
    
    for script in soup.find_all("script"):
        src = script.get("src")
        if src and "archive.org" in src:
            script.decompose()
    
    # Escape regex special characters
    escaped_keyword = re.escape(keyword)
    
    # 2. SEARCH VISIBLE TEXT - Find ALL occurrences
    body = soup.find("body")
    if body:
        text_content = body.get_text(separator=' ', strip=True)
        text_content = re.sub(r'\s+', ' ', text_content)
        
        pattern = re.compile(escaped_keyword, re.IGNORECASE)
        for match in pattern.finditer(text_content):
            start = max(0, match.start() - 30)
            end = min(len(text_content), match.end() + 30)
            snippet = "..." + text_content[start:end].replace('\n', ' ') + "..."
            
            matches.append({
                "timestamp": timestamp,
                "archiveUrl": archive_url,
                "matchType": "TEXT",
                "snippet": snippet
            })
    
    # 3. SEARCH JAVASCRIPT - Find ALL occurrences in each script tag
    for script in soup.find_all("script"):
        script_content = script.string
        if script_content:
            pattern = re.compile(escaped_keyword, re.IGNORECASE)
            for match in pattern.finditer(script_content):
                start = max(0, match.start() - 30)
                end = min(len(script_content), match.end() + 30)
                snippet = "..." + script_content[start:end].replace('\n', ' ').strip() + "..."
                
                matches.append({
                    "timestamp": timestamp,
                    "archiveUrl": archive_url,
                    "matchType": "JS",
                    "snippet": snippet
                })
    
    # 4. SEARCH COMMENTS - Find ALL occurrences
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for comment in comments:
        comment_text = str(comment)
        
        # Skip Wayback Machine comments
        if "FILE ARCHIVED ON" in comment_text:
            continue
        
        pattern = re.compile(escaped_keyword, re.IGNORECASE)
        for match in pattern.finditer(comment_text):
            start = max(0, match.start() - 30)
            end = min(len(comment_text), match.end() + 30)
            snippet = "..." + comment_text[start:end].strip() + "..."
            
            matches.append({
                "timestamp": timestamp,
                "archiveUrl": archive_url,
                "matchType": "COMMENT",
                "snippet": snippet
            })
    
    return matches


def send_sse_event(data: Dict) -> str:
    """Format data as SSE event"""
    return f"data: {json.dumps(data)}\n\n"


@app.route('/api/scan')
def scan():
    """SSE endpoint for forensic scanning"""
    domain = request.args.get('domain')
    year = request.args.get('year')
    keyword = request.args.get('keyword')
    limit = request.args.get('limit', '100')
    
    # Validate required parameters
    if not domain or not keyword:
        return {"error": "Missing required parameters: domain and keyword"}, 400
    
    try:
        limit = int(limit)
    except ValueError:
        limit = 100
    
    def generate():
        """Generator function for SSE stream"""
        try:
            # Fetch snapshots
            yield send_sse_event({
                "type": "progress",
                "message": f"Contacting Wayback Machine for: {domain}..."
            })
            
            snapshots = fetch_snapshots(domain, year, limit)
            
            if not snapshots:
                yield send_sse_event({
                    "type": "complete",
                    "message": "No snapshots found for this criteria."
                })
                return
            
            yield send_sse_event({
                "type": "progress",
                "message": f"Analyzing {len(snapshots)} snapshots for '{keyword}'...",
                "currentSnapshot": 0,
                "totalSnapshots": len(snapshots)
            })
            
            found_any = False
            
            # Process each snapshot
            for i, snapshot in enumerate(snapshots):
                timestamp = snapshot["timestamp"]
                original = snapshot["original"]
                archive_url = f"https://web.archive.org/web/{timestamp}/{original}"
                
                yield send_sse_event({
                    "type": "progress",
                    "message": f"Scanning snapshot: {timestamp}...",
                    "currentSnapshot": i + 1,
                    "totalSnapshots": len(snapshots)
                })
                
                try:
                    # Be polite to the Wayback Machine
                    time.sleep(random.uniform(0.5, 1.0))
                    
                    response = requests.get(archive_url, headers=HEADERS, timeout=TIMEOUT)
                    
                    if response.status_code == 200:
                        html = response.text
                        matches = extract_data(html, keyword, timestamp, archive_url)
                        
                        if matches:
                            found_any = True
                            
                            for match in matches:
                                yield send_sse_event({
                                    "type": "match",
                                    "match": match
                                })
                
                except Exception as e:
                    # Skip failed snapshots silently
                    continue
            
            # Send completion message
            if found_any:
                yield send_sse_event({
                    "type": "complete",
                    "message": "Scan complete."
                })
            else:
                yield send_sse_event({
                    "type": "complete",
                    "message": "Scan finished. No matches found."
                })
        
        except Exception as e:
            print(f"[Scan Error]: {e}")
            yield send_sse_event({
                "type": "error",
                "error": str(e)
            })
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/')
def index():
        """Simple landing page so root path doesn't return 404 on hosts."""
        html = """
        <!doctype html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>WayLook API</title>
            </head>
            <body>
                <h1>WayLook</h1>
                <p>The API is available at <a href="/api/scan">/api/scan</a>.</p>
                <p>If you intended to run the client web app, host the `client` app separately or build it into static files and serve them from this server.</p>
            </body>
        </html>
        """
        return Response(html, mimetype='text/html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True, threaded=True)
