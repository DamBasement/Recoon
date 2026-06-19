#!/usr/bin/env python3
"""
Triage of recon URLs using an LLM. Selects the most interesting endpoints
to investigate manually during a bug bounty engagement.

Backend: local Ollama by default (free), or the Claude API (paid, needs
an API key) via --provider claude — useful as a fallback if Ollama isn't
available or you want a quick quality check on a subset of URLs.

Features:
  - Reads URLs from a plain text file, from stdin ("-"), or from
    httpx-style JSON-lines (uses status_code/content_type as extra signal).
  - Deduplicates URLs ignoring tracking query parameters (utm_*, fbclid, ...).
  - Splits the work into batches to stay within the model's context window.
  - Retries failed batches with backoff, and can resume an interrupted run.
  - Saves both a JSON report and a human-readable Markdown report.
  - No third-party progress-bar library: status is printed as plain text,
    which renders reliably on every terminal.
"""

from __future__ import annotations  # allows "str | None" syntax on Python 3.9+

import warnings
# Silences urllib3's "NotOpenSSLWarning" on systems (e.g. macOS with the
# Apple-provided Python) where the ssl module is built against LibreSSL
# instead of OpenSSL. Purely cosmetic, must run before urllib3/requests load.
warnings.filterwarnings("ignore", message=".*OpenSSL.*")

import sys
import random
import os
import re
import json
import argparse
import datetime
import hashlib
import time
import threading
import requests
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

USELESS_EXTENSIONS = (
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.bmp', '.webp',
    '.css', '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.pdf', '.zip', '.rar', '.mp4', '.mp3', '.avi', '.map'
)

# Keywords used to prioritize the most "interesting" URLs
# before truncating the list to top-N (helps avoid wasting the
# model's context window on low-value assets)
PRIORITY_KEYWORDS = (
    'api', 'admin', 'debug', 'internal', 'staging', 'stage', 'dev',
    'test', 'beta', 'config', 'backup', 'swagger', 'graphql', 'upload',
    'account', 'user', 'profile', 'order', 'invoice', 'token', 'key',
    'password', 'id=', 'uid=', '.git', '.env', 'console', 'actuator'
)

# HTTP status codes worth a priority bonus when known (e.g. from httpx)
INTERESTING_STATUS_CODES = {200, 201, 301, 302, 401, 403}

# Query parameters stripped only for deduplication purposes (the original
# URL is kept untouched in the output/report)
TRACKING_PARAMS = {
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'fbclid', 'gclid', 'mc_cid', 'mc_eid', 'ref'
}


# --------------------------------------------------------------------------
# Plain-text status line (replaces any progress-bar library)
# --------------------------------------------------------------------------

class LiveLine:
    """Prints a single status line that updates itself in place using a
    carriage return. Uses no colors and no special characters, so it
    renders identically on every terminal."""

    def __init__(self):
        self._lock = threading.Lock()
        self._last_len = 0

    def update(self, text: str) -> None:
        with self._lock:
            pad = max(0, self._last_len - len(text))
            sys.stdout.write("\r" + text + (" " * pad))
            sys.stdout.flush()
            self._last_len = len(text)

    def done(self, final_text: str | None = None) -> None:
        with self._lock:
            if final_text is not None:
                pad = max(0, self._last_len - len(final_text))
                sys.stdout.write("\r" + final_text + (" " * pad) + "\n")
            else:
                sys.stdout.write("\n")
            sys.stdout.flush()
            self._last_len = 0


# --------------------------------------------------------------------------
# Input loading
# --------------------------------------------------------------------------

def read_raw_lines(file_path: str) -> list[str]:
    if file_path == '-':
        data = sys.stdin.read()
    else:
        if not os.path.exists(file_path):
            print(f"[-] Error: file {file_path} does not exist.")
            sys.exit(1)
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = f.read()
    return [line.strip() for line in data.splitlines() if line.strip()]


def parse_records(lines: list[str]) -> list[dict]:
    """Turns raw lines into records. Auto-detects httpx-style JSON-lines
    (one JSON object per line, with a "url" or "input" field) and keeps
    status_code/content_type/content_length when available; otherwise
    treats each line as a plain URL."""
    if not lines:
        return []

    is_jsonl = False
    try:
        first = json.loads(lines[0])
        if isinstance(first, dict) and ('url' in first or 'input' in first):
            is_jsonl = True
    except json.JSONDecodeError:
        is_jsonl = False

    records = []
    if is_jsonl:
        for line in lines:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get('url') or obj.get('input')
            if not url:
                continue
            records.append({
                'url': url,
                'status_code': obj.get('status_code'),
                'content_length': obj.get('content_length'),
                'content_type': obj.get('content_type'),
            })
    else:
        for line in lines:
            records.append({'url': line, 'status_code': None,
                             'content_length': None, 'content_type': None})
    return records


def filter_records(records: list[dict], domain_filter: str | None) -> list[dict]:
    filtered = []
    for r in records:
        u = r['url']
        if u.lower().endswith(USELESS_EXTENSIONS):
            continue
        if domain_filter and domain_filter.lower() not in u.lower():
            continue
        filtered.append(r)
    return filtered


def normalize_for_dedup(url: str) -> str:
    """Builds a comparison key that ignores tracking query parameters,
    so URLs that differ only by utm_source/fbclid/etc. are treated as
    duplicates. The original URL is never altered in the output."""
    try:
        parts = urlsplit(url)
        kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                if k.lower() not in TRACKING_PARAMS]
        kept.sort()
        new_query = urlencode(kept)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, '')).lower()
    except ValueError:
        return url.lower()


def dedup_records(records: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for r in records:
        key = normalize_for_dedup(r['url'])
        if key in seen:
            continue
        seen.add(key)
        result.append(r)
    return result


def score_record(r: dict) -> int:
    s = sum(1 for kw in PRIORITY_KEYWORDS if kw in r['url'].lower())
    if r.get('status_code') in INTERESTING_STATUS_CODES:
        s += 2
    ct = (r.get('content_type') or '').lower()
    if 'json' in ct or 'xml' in ct:
        s += 1
    return s


def sort_by_priority(records: list[dict]) -> list[dict]:
    return sorted(records, key=score_record, reverse=True)


def format_for_prompt(r: dict) -> str:
    extras = []
    if r.get('status_code') is not None:
        extras.append(f"status:{r['status_code']}")
    if r.get('content_type'):
        extras.append(f"type:{r['content_type']}")
    if r.get('content_length') is not None:
        extras.append(f"len:{r['content_length']}")
    if extras:
        return f"{r['url']} [{', '.join(extras)}]"
    return r['url']


# --------------------------------------------------------------------------
# Ollama calls (with retry)
# --------------------------------------------------------------------------

class Heartbeat:
    """Updates a LiveLine with elapsed seconds while waiting for the
    model's first token (prompt processing on CPU can take a while with
    no visible activity otherwise). Stops as soon as tokens start arriving."""

    def __init__(self, label: str, line: LiveLine):
        self._stop = threading.Event()
        self._start = time.time()
        self._line = line
        self._thread = threading.Thread(target=self._run, args=(label,), daemon=True)
        self._thread.start()

    def _run(self, label: str) -> None:
        while not self._stop.is_set():
            elapsed = int(time.time() - self._start)
            self._line.update(f"[*] {label}: waiting for model... {elapsed}s")
            time.sleep(1)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)


def _request_with_retry(payload: dict, ollama_url: str, timeout: int,
                         batch_label: str, max_retries: int, retry_delay: int):
    for attempt in range(1, max_retries + 2):
        response = None
        try:
            response = requests.post(ollama_url, json=payload, stream=True, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print(f"[-] {batch_label}: connection error (attempt {attempt}/{max_retries + 1}). "
                  f"Is Ollama running (ollama serve)?")
        except requests.exceptions.Timeout:
            print(f"[-] {batch_label}: request timed out (attempt {attempt}/{max_retries + 1}).")

        if response is not None:
            if response.status_code == 200:
                return response
            print(f"[-] {batch_label}: Ollama returned HTTP {response.status_code} "
                  f"(attempt {attempt}/{max_retries + 1}).")

        if attempt <= max_retries:
            wait = retry_delay * attempt
            print(f"[*] {batch_label}: retrying in {wait}s...")
            time.sleep(wait)

    return None


def build_analysis_prompt(prompt_lines: list[str], target: str) -> str:
    return f"""
You are a Bug Bounty specialist. Analyze these URLs from the target {target}.
Some entries may include extra recon signals in brackets (HTTP status, content type, length).
Select the most critical or interesting endpoints for logic bugs
(IDOR, vulnerable APIs, sensitive parameters, stage/dev environments).

URLs:
{chr(10).join(prompt_lines)}

Respond ONLY in JSON format with this exact structure:
{{
    "target_analysis": [
        {{"url": "string", "potential_flaw_type": "string", "investigation_reason": "string", "priority": "HIGH"}}
    ]
}}
"""


def call_ollama(prompt_lines: list[str], model: str, ollama_url: str, target: str,
                 timeout: int, batch_label: str, max_retries: int, retry_delay: int,
                 temperature: float, seed: int | None, max_tokens: int = 2048) -> dict | None:
    prompt = build_analysis_prompt(prompt_lines, target)
    # num_predict caps the output tokens — prevents the model from going
    # into an infinite loop on "interesting" batches (seen: 25k+ tokens).
    # 2048 is more than enough for a full JSON response on 50 URLs.
    options = {"temperature": temperature, "num_predict": max_tokens}
    if seed is not None:
        options["seed"] = seed

    payload = {"model": model, "prompt": prompt, "stream": True, "format": "json", "options": options}

    response = _request_with_retry(payload, ollama_url, timeout, batch_label, max_retries, retry_delay)
    if response is None:
        print(f"[-] {batch_label}: giving up after {max_retries + 1} attempt(s).")
        return None

    full_response = ""
    line = LiveLine()
    hb = Heartbeat(batch_label, line)
    token_count = 0
    last_update = 0.0
    start_gen = None
    try:
        for raw_line in response.iter_lines():
            if not raw_line:
                continue
            if start_gen is None:
                hb.stop()
                start_gen = time.time()
            try:
                chunk = json.loads(raw_line.decode('utf-8', errors='replace'))
            except json.JSONDecodeError:
                continue
            full_response += chunk.get("response", "")
            token_count += 1

            now = time.time()
            if now - last_update > 0.15:
                elapsed = now - start_gen
                rate = token_count / elapsed if elapsed > 0 else 0.0
                line.update(f"[*] {batch_label}: generating... {token_count} tokens "
                            f"({elapsed:.1f}s, {rate:.1f} tok/s)")
                last_update = now
    finally:
        hb.stop()
        if start_gen is not None:
            elapsed = time.time() - start_gen
            rate = token_count / elapsed if elapsed > 0 else 0.0
            line.done(f"[*] {batch_label}: generated {token_count} tokens in {elapsed:.1f}s "
                      f"({rate:.1f} tok/s)")
        else:
            line.done()

    try:
        return json.loads(full_response)
    except json.JSONDecodeError:
        print(f"[-] {batch_label}: model response was not valid JSON:")
        print(full_response[:500])
        return None


# --------------------------------------------------------------------------
# Claude API calls (optional paid backend, with retry)
# --------------------------------------------------------------------------

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_API_VERSION = "2023-06-01"


def _claude_request_with_retry(headers: dict, body: dict, timeout: int,
                                batch_label: str, max_retries: int, retry_delay: int):
    for attempt in range(1, max_retries + 2):
        response = None
        try:
            response = requests.post(CLAUDE_API_URL, headers=headers, json=body, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print(f"[-] {batch_label}: connection error to the Claude API "
                  f"(attempt {attempt}/{max_retries + 1}).")
        except requests.exceptions.Timeout:
            print(f"[-] {batch_label}: request to the Claude API timed out "
                  f"(attempt {attempt}/{max_retries + 1}).")

        if response is not None:
            if response.status_code == 200:
                return response
            print(f"[-] {batch_label}: Claude API returned HTTP {response.status_code} "
                  f"(attempt {attempt}/{max_retries + 1}): {response.text[:200]}")

        if attempt <= max_retries:
            wait = retry_delay * attempt
            print(f"[*] {batch_label}: retrying in {wait}s...")
            time.sleep(wait)

    return None


def call_claude(prompt_lines: list[str], model: str, api_key: str, target: str,
                 timeout: int, batch_label: str, max_retries: int, retry_delay: int,
                 temperature: float) -> dict | None:
    prompt = build_analysis_prompt(prompt_lines, target)
    headers = {
        "x-api-key": api_key,
        "anthropic-version": CLAUDE_API_VERSION,
        "content-type": "application/json",
    }
    body = {
        "model": model,
        "max_tokens": 2048,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }

    line = LiveLine()
    hb = Heartbeat(batch_label, line)
    response = _claude_request_with_retry(headers, body, timeout, batch_label, max_retries, retry_delay)
    hb.stop()
    line.done()

    if response is None:
        print(f"[-] {batch_label}: giving up after {max_retries + 1} attempt(s).")
        return None

    try:
        data = response.json()
        text = "".join(block.get("text", "") for block in data.get("content", [])
                        if block.get("type") == "text")
    except (json.JSONDecodeError, AttributeError):
        print(f"[-] {batch_label}: unexpected response shape from the Claude API.")
        return None

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        print(f"[-] {batch_label}: model response was not valid JSON:")
        print(text[:500])
        return None


# --------------------------------------------------------------------------
# Resume / incremental state
# --------------------------------------------------------------------------

def compute_fingerprint(urls: list[str], model: str, batch_size: int, provider: str) -> str:
    payload = json.dumps({"urls": urls, "model": model, "batch_size": batch_size,
                           "provider": provider}, sort_keys=True)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def load_state(state_path: str) -> dict | None:
    if not os.path.exists(state_path):
        return None
    try:
        with open(state_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def save_state(state_path: str, fingerprint: str, completed_batches: set, results: list) -> None:
    tmp_path = state_path + ".tmp"
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump({
            "fingerprint": fingerprint,
            "completed_batches": sorted(completed_batches),
            "results": results,
        }, f)
    os.replace(tmp_path, state_path)


# --------------------------------------------------------------------------
# Per-target persistent files (findings checklist + seen-URLs tracking)
# --------------------------------------------------------------------------

VALID_STATUSES = ("to_test", "confirmed", "false_positive")


def sanitize_filename(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9_.-]', '_', s)


def state_dir_for_target(target: str) -> str:
    """All per-target persistent files live under .recon_state/<target>/,
    so different bug bounty programs never collide even if you run the
    script from the same working directory or forget to organize folders."""
    d = os.path.join(".recon_state", sanitize_filename(target))
    os.makedirs(d, exist_ok=True)
    return d


def default_findings_db_path(target: str) -> str:
    return os.path.join(state_dir_for_target(target), "findings.json")


def default_seen_urls_path(target: str) -> str:
    return os.path.join(state_dir_for_target(target), "seen_urls.json")


def load_json_dict(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_json_dict(path: str, data: dict) -> None:
    tmp_path = path + ".tmp"
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)


def load_seen_keys(path: str) -> set:
    data = load_json_dict(path)
    return set(data.get('keys', []))


def save_seen_keys(path: str, keys: set) -> None:
    save_json_dict(path, {"keys": sorted(keys)})


def merge_findings(db: dict, results: list[dict], timestamp: str) -> dict:
    """Adds new findings as 'to_test' and refreshes metadata for ones already
    known, without ever overwriting a status the user already set by hand."""
    for item in results:
        url = item.get('url')
        if not url:
            continue
        entry = db.get(url)
        if entry is None:
            db[url] = {
                "status": "to_test",
                "priority": item.get("priority", "UNKNOWN"),
                "potential_flaw_type": item.get("potential_flaw_type", ""),
                "investigation_reason": item.get("investigation_reason", ""),
                "first_seen": timestamp,
                "last_seen": timestamp,
            }
        else:
            entry["priority"] = item.get("priority", entry.get("priority", "UNKNOWN"))
            entry["potential_flaw_type"] = item.get("potential_flaw_type", entry.get("potential_flaw_type", ""))
            entry["investigation_reason"] = item.get("investigation_reason", entry.get("investigation_reason", ""))
            entry["last_seen"] = timestamp
    return db


# --------------------------------------------------------------------------
# Markdown report
# --------------------------------------------------------------------------

def build_markdown_report(report: dict, findings_db: dict) -> str:
    db_status_counts: dict[str, int] = {}
    for entry in findings_db.values():
        s = entry.get('status', 'to_test')
        db_status_counts[s] = db_status_counts.get(s, 0) + 1
    db_breakdown = ", ".join(f"{v} {k}" for k, v in sorted(db_status_counts.items())) or "none yet"

    lines = [
        f"# Recon Triage Report — {report['target']}",
        "",
        f"- Generated: {report['timestamp']}",
        f"- URLs analyzed: {report['urls_analyzed']}",
        f"- Batches: {report['stats']['total_batches']} "
        f"(failed: {report['stats']['failed_batches']})",
        f"- Findings returned by the model (this run): {len(report['target_analysis'])}",
        f"- Findings checklist total, all runs for this target: {db_breakdown}",
        "",
        "Status shown next to each finding comes from the findings database. "
        "To update it, use `--set-status \"<url>\" <to_test|confirmed|false_positive>` "
        "(checking the box here is just visual, it doesn't update the database).",
        "",
    ]

    grouped: dict[str, list[dict]] = {}
    for item in report['target_analysis']:
        key = str(item.get('priority', 'UNKNOWN')).upper()
        grouped.setdefault(key, []).append(item)

    order = ["HIGH", "MEDIUM", "LOW"]
    keys = [k for k in order if k in grouped] + [k for k in grouped if k not in order]

    for key in keys:
        items = grouped[key]
        lines.append(f"## Priority: {key} ({len(items)})")
        lines.append("")
        for item in items:
            url = item.get('url', '?')
            status = findings_db.get(url, {}).get('status', 'to_test')
            checkbox = "[x]" if status == "confirmed" else "[ ]"
            status_label = "" if status == "to_test" else f" _(status: {status})_"
            lines.append(f"- {checkbox} **{url}**{status_label}")
            lines.append(f"  - Type: {item.get('potential_flaw_type', '?')}")
            lines.append(f"  - Why: {item.get('investigation_reason', '?')}")
        lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------
# Main pipeline
# --------------------------------------------------------------------------

def analyze_recon(file_path: str, model: str, ollama_url: str,
                   top_n: int, batch_size: int, target: str,
                   domain_filter: str | None, timeout: int, output_path: str,
                   max_retries: int, retry_delay: int, resume: bool,
                   markdown_path: str, temperature: float, seed: int | None,
                   provider: str, api_key: str | None, diff_only: bool,
                   seen_urls_path: str, findings_db_path: str, max_tokens: int):

    print("[*] Loading and cleaning the URL list...")
    records = read_raw_lines(file_path)
    records = parse_records(records)
    records = filter_records(records, domain_filter)
    records = dedup_records(records)

    seen_keys = load_seen_keys(seen_urls_path)
    current_keys = {normalize_for_dedup(r['url']) for r in records}
    new_keys = current_keys - seen_keys
    print(f"[*] {len(new_keys)} of {len(records)} URL(s) are new since the last run for this target "
          f"({seen_urls_path}).")

    if diff_only:
        records = [r for r in records if normalize_for_dedup(r['url']) in new_keys]
        print(f"[*] --diff-only: analyzing only the {len(records)} new URL(s).")

    save_seen_keys(seen_urls_path, seen_keys | current_keys)

    if diff_only and not records:
        print("[*] No new URLs since the last run — nothing to analyze.")
        return

    records = sort_by_priority(records)[:top_n]

    if not records:
        print("[-] No URLs left after filtering.")
        return

    urls = [r['url'] for r in records]
    prompt_lines = [format_for_prompt(r) for r in records]

    num_batches = (len(records) + batch_size - 1) // batch_size
    print(f"[*] {len(records)} URLs selected, split into {num_batches} batch(es) "
          f"of up to {batch_size} URLs (to stay within the model's context window).\n")

    fingerprint = compute_fingerprint(urls, model, batch_size, provider)
    state_path = output_path + ".state.json"

    completed_batches: set = set()
    aggregated_results: list = []
    if resume:
        state = load_state(state_path)
        if state and state.get('fingerprint') == fingerprint:
            completed_batches = set(state.get('completed_batches', []))
            aggregated_results = list(state.get('results', []))
            print(f"[*] Resuming: {len(completed_batches)}/{num_batches} batch(es) "
                  f"already completed in a previous run.")
        elif state:
            print("[!] Found a previous state file but it doesn't match this run "
                  "(different URLs/model/batch-size). Starting fresh.")

    failed_batches = 0
    for i in range(0, len(prompt_lines), batch_size):
        batch_num = i // batch_size + 1
        batch_label = f"batch {batch_num}/{num_batches}"

        if batch_num in completed_batches:
            print(f"[*] {batch_label}: already done, skipping.")
            continue

        batch = prompt_lines[i:i + batch_size]
        print(f"[*] {batch_label}: sending {len(batch)} URLs to "
              f"{'the Claude API' if provider == 'claude' else 'Ollama'}...")

        batch_start = time.time()
        if provider == "claude":
            result = call_claude(batch, model, api_key, target, timeout,
                                  batch_label, max_retries, retry_delay, temperature)
        else:
            result = call_ollama(batch, model, ollama_url, target, timeout,
                                  batch_label, max_retries, retry_delay,
                                  temperature, seed, max_tokens)
        elapsed = time.time() - batch_start

        if result and "target_analysis" in result:
            n_found = len(result["target_analysis"])
            aggregated_results.extend(result["target_analysis"])
            print(f"[+] {batch_label}: done in {elapsed:.1f}s, {n_found} finding(s). "
                  f"({batch_num}/{num_batches} batches completed)")
        else:
            failed_batches += 1
            print(f"[-] {batch_label}: failed after {elapsed:.1f}s, no results. "
                  f"({batch_num}/{num_batches} batches completed)")

        completed_batches.add(batch_num)
        save_state(state_path, fingerprint, completed_batches, aggregated_results)

    if not aggregated_results:
        print("[-] No usable results were obtained from any batch. "
              f"Partial state kept at: {state_path}")
        return

    final_report = {
        "target": target,
        "timestamp": datetime.datetime.now().isoformat(),
        "urls_analyzed": len(records),
        "stats": {
            "total_batches": num_batches,
            "failed_batches": failed_batches,
        },
        "target_analysis": aggregated_results,
    }

    print("\n[+] Analysis complete!")
    priority_counts: dict[str, int] = {}
    for item in aggregated_results:
        key = str(item.get('priority', 'UNKNOWN')).upper()
        priority_counts[key] = priority_counts.get(key, 0) + 1
    breakdown = ", ".join(f"{v} {k}" for k, v in sorted(priority_counts.items()))
    print(f"[+] {len(aggregated_results)} finding(s) total ({breakdown}).")

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(final_report, f, indent=4, ensure_ascii=False)
    print(f"[+] JSON report saved to: {output_path}")

    findings_db = load_json_dict(findings_db_path)
    findings_db = merge_findings(findings_db, aggregated_results, final_report["timestamp"])
    save_json_dict(findings_db_path, findings_db)
    db_status_counts: dict[str, int] = {}
    for entry in findings_db.values():
        s = entry.get('status', 'to_test')
        db_status_counts[s] = db_status_counts.get(s, 0) + 1
    db_breakdown = ", ".join(f"{v} {k}" for k, v in sorted(db_status_counts.items()))
    print(f"[+] Findings checklist updated: {findings_db_path} ({db_breakdown})")

    with open(markdown_path, 'w', encoding='utf-8') as f:
        f.write(build_markdown_report(final_report, findings_db))
    print(f"[+] Markdown report saved to: {markdown_path}")

    if failed_batches == 0:
        try:
            os.remove(state_path)
        except OSError:
            pass
    else:
        print(f"[!] {failed_batches} batch(es) failed. State kept at {state_path} "
              f"— rerun with --resume to retry just those.")


# --------------------------------------------------------------------------
# Retro banner (plain ASCII only, color only when attached to a real terminal)
# --------------------------------------------------------------------------

_RECOON_LOGO = [
    "######   #######   ######   #####    #####   ##   ##",
    "##   ##  ##       ##       ##   ##  ##   ##  ###  ##",
    "##   ##  #####    ##       ##   ##  ##   ##  #### ##",
    "######   ##       ##       ##   ##  ##   ##  ## ####",
    "##  ##   ##       ##       ##   ##  ##   ##  ##  ###",
    "##   ##  #######   ######   #####    #####   ##   ##",
]

_CYBERPUNK_LINES = (
    "jacking into the grid, sniffing out forgotten bugs_",
    "trash by day, zero-day by night_",
    "scanning the neon sprawl for cracks in the code_",
    "one raccoon's 404 is another's bounty_",
)


def print_banner() -> None:
    use_color = sys.stdout.isatty()
    cyan = "\033[96m" if use_color else ""
    magenta = "\033[95m" if use_color else ""
    bold = "\033[1m" if use_color else ""
    reset = "\033[0m" if use_color else ""

    width = max(len(line) for line in _RECOON_LOGO) + 4
    border = "=" * width
    colors = [magenta, magenta, cyan, cyan, magenta, magenta]

    print(f"{cyan}{border}{reset}")
    for color, line in zip(colors, _RECOON_LOGO):
        print(f"{color}{bold}  {line}{reset}")
    print(f"{cyan}{border}{reset}")
    print(f"{magenta}  >> {random.choice(_CYBERPUNK_LINES)}{reset}")
    print(f"{cyan}  bug bounty url triage // powered by local AI{reset}")
    print(f"{magenta}  [ SYSTEM ONLINE ]{reset}")
    print(f"{cyan}{border}{reset}")
    print()


def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="Triage recon URLs with an LLM (local Ollama by default, or the Claude API)."
    )
    parser.add_argument(
        "file", nargs='?', default=None,
        help="Text file with one URL per line, httpx-style JSON-lines, or '-' to read from stdin. "
             "Not needed when only using --set-status."
    )
    parser.add_argument("--target", default="target", help="Target name/domain used in the prompt.")
    parser.add_argument("--domain-filter", default=None,
                         help="If set, only keep URLs containing this string.")
    parser.add_argument("--provider", choices=["ollama", "claude"], default="ollama",
                         help="Backend to use: 'ollama' (free, local, default) or "
                              "'claude' (paid, cloud, needs an API key).")
    parser.add_argument("--model", default=None,
                         help="Model name. Defaults to 'llama3' for --provider ollama "
                              "(also worth trying: qwen2.5:7b, hermes2-pro), or "
                              "'claude-haiku-4-5-20251001' for --provider claude.")
    parser.add_argument("--api-key", default=None,
                         help="Anthropic API key, only used with --provider claude. "
                              "Falls back to the ANTHROPIC_API_KEY environment variable.")
    parser.add_argument("--ollama-url", default="http://localhost:11434/api/generate")
    parser.add_argument("--top", type=int, default=150, help="Maximum number of URLs to analyze.")
    parser.add_argument("--batch-size", type=int, default=50,
                         help="URLs per request, to avoid exceeding the model's context window.")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout per request, in seconds.")
    parser.add_argument("--max-retries", type=int, default=2,
                         help="Retries for a batch before giving up on it.")
    parser.add_argument("--retry-delay", type=int, default=5,
                         help="Base delay in seconds between retries (grows linearly).")
    parser.add_argument("--resume", action="store_true",
                         help="Resume a previous interrupted run for the same output file.")
    parser.add_argument("--diff-only", action="store_true",
                         help="Only analyze URLs not seen in a previous run for this target "
                              "(tracked in the seen-urls file). Useful for re-running on an "
                              "updated recon dump without re-analyzing everything.")
    parser.add_argument("--seen-urls-db", default=None,
                         help="Path to the seen-urls tracking file (default: derived from --target).")
    parser.add_argument("--findings-db", default=None,
                         help="Path to the findings checklist database (default: derived from --target).")
    parser.add_argument("--set-status", nargs=2, metavar=("URL", "STATUS"), action="append",
                         help="Set a finding's status in the findings database and exit without "
                              "running a new analysis. STATUS must be one of: "
                              f"{', '.join(VALID_STATUSES)}. Can be repeated.")
    parser.add_argument("--temperature", type=float, default=0.1,
                         help="Sampling temperature. Lower (e.g. 0) = more consistent results "
                              "across runs; higher = more varied/creative. Default: 0.1.")
    parser.add_argument("--max-tokens", type=int, default=2048,
                         help="Maximum tokens the model can generate per batch. "
                              "Prevents runaway generation on 'interesting' batches. Default: 2048.")
    parser.add_argument("--seed", type=int, default=None,
                         help="Optional fixed seed for more reproducible results "
                              "(supported by most Ollama models, not a 100%% guarantee).")
    parser.add_argument("--output", default=None, help="Path for the output JSON report.")
    parser.add_argument("--markdown-output", default=None,
                         help="Path for the human-readable Markdown report (default: same name as --output).")
    args = parser.parse_args()

    findings_db_path = args.findings_db or default_findings_db_path(args.target)

    if args.set_status:
        db = load_json_dict(findings_db_path)
        now = datetime.datetime.now().isoformat()
        for url, status in args.set_status:
            if status not in VALID_STATUSES:
                print(f"[-] Invalid status '{status}' for {url}. "
                      f"Must be one of: {', '.join(VALID_STATUSES)}.")
                sys.exit(1)
            entry = db.get(url)
            if entry is None:
                entry = {"status": status, "priority": "UNKNOWN", "potential_flaw_type": "",
                          "investigation_reason": "(added manually via --set-status)",
                          "first_seen": now, "last_seen": now}
                db[url] = entry
            else:
                entry["status"] = status
                entry["last_seen"] = now
            print(f"[+] {url}: status set to '{status}'.")
        save_json_dict(findings_db_path, db)
        print(f"[+] Findings database saved to: {findings_db_path}")
        return

    if args.file is None:
        parser.error("the 'file' argument is required unless using --set-status")

    seen_urls_path = args.seen_urls_db or default_seen_urls_path(args.target)

    if args.model is None:
        args.model = "claude-haiku-4-5-20251001" if args.provider == "claude" else "llama3"

    api_key = None
    if args.provider == "claude":
        api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            print("[-] --provider claude requires an API key: pass --api-key or set "
                  "the ANTHROPIC_API_KEY environment variable.")
            sys.exit(1)

    output_path = args.output
    if output_path is None:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"recon_report_{ts}.json"

    if args.markdown_output:
        markdown_path = args.markdown_output
    elif output_path.endswith('.json'):
        markdown_path = output_path[:-5] + '.md'
    else:
        markdown_path = output_path + '.md'

    analyze_recon(
        file_path=args.file,
        model=args.model,
        ollama_url=args.ollama_url,
        top_n=args.top,
        batch_size=args.batch_size,
        target=args.target,
        domain_filter=args.domain_filter,
        timeout=args.timeout,
        output_path=output_path,
        max_retries=args.max_retries,
        retry_delay=args.retry_delay,
        resume=args.resume,
        markdown_path=markdown_path,
        temperature=args.temperature,
        seed=args.seed,
        provider=args.provider,
        api_key=api_key,
        diff_only=args.diff_only,
        seen_urls_path=seen_urls_path,
        findings_db_path=findings_db_path,
        max_tokens=args.max_tokens,
    )


if __name__ == "__main__":
    main()
