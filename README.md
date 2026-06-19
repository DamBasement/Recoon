<img width="1320" height="803" alt="RecoonLogo" src="https://github.com/user-attachments/assets/93ccd19d-042d-491c-a954-33c18ddf7876"/>

# RECOON 🦝

A passive recon pipeline + AI triage toolkit for bug bounty hunting.
Everything runs **locally and for free** via [Ollama](https://ollama.com).

```
  /\_____/\     R E C O O N . S H
 (  o   o  )   passive recon pipeline
 (  =   =  )   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  \ ----- /    subfinder + amass + httpx + gau
   )     (     + RECOON AI triage
  (_|___|_)
  [  [ ]  ]    >> find what they forgot to hide_
```

---

## What it is

RECOON is two scripts that work together:

- **`recon.sh`** — the full pipeline: subdomain enumeration, host validation,
  historical URL collection, and automatic AI triage. Run this once on a target
  and go get a coffee.

- **`recoon.py`** — the AI triage engine. Takes a list of URLs (from gau, httpx,
  or any other tool) and uses a local LLM to rank the most interesting endpoints
  to investigate manually. Can also be used standalone on any URL file.

Neither script actively tests anything. They help you decide **where to start
looking** on Burp — the manual work is still yours.

---

## Requirements

### Tools (install once)
```bash
# macOS
brew install subfinder amass httpx gau python3 ollama

# Pull a model (qwen2.5:7b is the recommended default)
ollama pull qwen2.5:7b
```

Check your model tag with `ollama list` — use the exact name shown there
(e.g. `qwen2.5:7b`, not just `qwen2.5`).

### Python
```bash
pip install requests
```

---

## Project structure

Keep both scripts in the same folder per program:

```
YourTarget/
├── recon.sh          ← pipeline script
├── recoon.py         ← AI triage engine
├── .recon_state/     ← auto-created, per-target state
│   └── example.com/
│       ├── findings.json    # persistent checklist (survives every run)
│       └── seen_urls.json   # URLs already analyzed (for --diff-only)
├── subs.txt
├── live_hosts.txt / live_hosts.json
├── all_urls.txt
├── sensitive_files.txt
├── recon_report_hosts_<timestamp>.json / .md
└── recon_report_urls_<timestamp>.json  / .md
```

Use a separate folder for each bug bounty program — state files are kept
per `--target` value so different programs never mix, but it's still cleaner.

---

## Quick start

### Full pipeline (recommended)

```bash
chmod +x recon.sh
./recon.sh example.com qwen2.5:7b
```

That's it. When it finishes you'll have two Markdown reports:
- `recon_report_hosts_<timestamp>.md` — live hosts triage (fast, with tech/status)
- `recon_report_urls_<timestamp>.md` — historical URL triage (deeper, from gau)

### Standalone triage on an existing URL file

```bash
python3 recoon.py urls.txt --target "example.com" --domain-filter "example.com" --model qwen2.5:7b
```

Useful when you already have a URL list from another tool and just want the AI pass.

---

## What recon.sh does, step by step

**Step 1 — Subdomain enumeration** with `subfinder` + `amass` (passive only —
no active DNS bruteforce). Results go into `subs.txt`.

> ⚠️ Always pass the **root domain** (`example.com`), not a subdomain
> (`www.example.com`). The script warns you if it detects a `www.*` input
> and gives you 5 seconds to abort.

**Step 2 — Live host validation** with `httpx`. Probes every subdomain and keeps
only those that actually respond. Produces `live_hosts.txt` (plain list) and
`live_hosts.json` (rich JSON with status code, title, technologies).

**Step 3 — Historical URL collection** with `gau`. Fetches URLs from Wayback
Machine and other public archives for every live host, going back to 2023.
Results go into `all_urls.txt`. This step takes the most time (5–30 min
depending on the target size).

**Step 4 — Quick grep** for obviously interesting patterns (`.env`, `.sql`,
`.bak`, `/admin`, `/api`, `/.git`, etc.) into `sensitive_files.txt`.
Worth a manual look regardless of the AI output.

**Step 5 — RECOON AI triage, two passes:**
- Pass 1: `live_hosts.json` → fast triage with status/tech metadata
- Pass 2: `all_urls.txt` → deeper triage on historical URLs

Both passes run automatically, no extra commands needed.

---

## What recoon.py does

Takes a URL file (plain text, one per line, or httpx JSON-lines) and:

1. Drops static assets (images, CSS, fonts, etc.)
2. Deduplicates ignoring tracking params (`utm_*`, `fbclid`, etc.)
3. Scores URLs by priority keywords (`api`, `admin`, `id=`, `.git`, `token`, etc.)
   and, if available, HTTP status code and content-type
4. Splits into batches of 50 URLs (configurable) to stay within the model's
   context window
5. Sends each batch to Ollama asking for the most interesting endpoints for
   logic bugs (IDOR, exposed APIs, staging environments, sensitive parameters)
6. Saves results as JSON + Markdown, grouped by priority
7. Updates a **persistent findings checklist** in `.recon_state/<target>/`

The model's output (`num_predict` capped at 2048 tokens per batch) prevents
runaway generation on complex batches.

---

## Managing findings across runs

Every finding goes into `.recon_state/<target>/findings.json` with status
`to_test`. After you test something on Burp, update it:

```bash
# Mark as confirmed vulnerability
python3 recoon.py --target "example.com" \
  --set-status "https://example.com/api/v1/orders?id=2" confirmed

# Mark as false positive
python3 recoon.py --target "example.com" \
  --set-status "https://example.com/user/password" false_positive
```

Valid statuses: `to_test`, `confirmed`, `false_positive`.

The Markdown report shows a checkbox next to each finding with the current
status — but it's display-only. Always use `--set-status` to update the database.

---

## Re-running on a target (diff-only)

When you do a new recon pass weeks later and have a fresh URL dump:

```bash
# First run — analyzes everything, saves seen URLs
./recon.sh example.com qwen2.5:7b

# Later runs — only analyzes new URLs not seen before
python3 recoon.py new_urls.txt --target "example.com" --diff-only
```

The `--target` value must match exactly between runs for the comparison to work.

---

## Telegram notifications (optional)

`recon.sh` can send you a Telegram message when a run completes.
Set up once, never touch again:

```bash
# Add to ~/.zshrc or ~/.bashrc
export TELEGRAM_BOT_TOKEN="your_bot_token_here"
export TELEGRAM_CHAT_ID="your_chat_id_here"
```

To get these values:
1. Open Telegram and search for `@BotFather`
2. Send `/newbot` and follow the prompts → you get your token
3. Start a chat with your bot, then visit:
   `https://api.telegram.org/bot<TOKEN>/getUpdates`
   and look for `"chat":{"id":...}` → that's your chat ID

If the variables are not set, notifications are silently skipped —
the script works normally either way. **Never put credentials directly
in the script file** — use environment variables or `.env` files that
are listed in `.gitignore`.

---

## Using the Claude API instead of Ollama (optional, paid)

By default everything stays local and free. If you want to use Anthropic's
Claude API instead:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python3 recoon.py urls.txt --target "example.com" --provider claude
```

Defaults to `claude-haiku-4-5-20251001` (cheapest). Cost for a typical
100–200 URL analysis: a few cents. For the full pipeline on a large target
(thousands of URLs after filtering): rarely more than $0.50.

---

## Multiple programs

Each program gets its own folder and its own `--target` value:

```bash
mkdir ProgramA && cp recon.sh recoon.py ProgramA/ && cd ProgramA
./recon.sh target-a.com qwen2.5:7b

mkdir ProgramB && cp recon.sh recoon.py ProgramB/ && cd ProgramB
./recon.sh target-b.com qwen2.5:7b
```

State files never mix between programs.

---

## Main options — recoon.py

| Option | Description | Default |
|---|---|---|
| `--target` | Program/target name (used for state file separation) | `target` |
| `--domain-filter` | Keep only URLs containing this string | none |
| `--provider` | `ollama` (free, local) or `claude` (paid, cloud) | `ollama` |
| `--model` | Model name | `qwen2.5:7b` / `claude-haiku-4-5-20251001` |
| `--top` | Max URLs to analyze per run | `150` |
| `--batch-size` | URLs per request to the model | `50` |
| `--max-tokens` | Max tokens the model can generate per batch | `2048` |
| `--temperature` | Model creativity (lower = more consistent) | `0.1` |
| `--seed` | Fixed seed for reproducible results (Ollama only) | none |
| `--diff-only` | Only analyze URLs new since last run | off |
| `--resume` | Resume an interrupted run | off |
| `--set-status URL STATUS` | Update a finding's status and exit | — |
| `--output` | Custom JSON report path | auto timestamp |
| `--markdown-output` | Custom Markdown report path | auto timestamp |

Full list: `python3 recoon.py -h`

---

## Things to keep in mind

The model judges only from the URL text (and status/content-type when available):
**it does not actively test anything**. Every finding is a hypothesis to verify
manually on Burp, not a confirmed vulnerability.

Always check the program's scope and rules before testing anything actively —
some programs exclude specific subdomains or prohibit automated scanning even
when passive recon is allowed.
