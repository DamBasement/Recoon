# RECOON

A Python script that uses an LLM (locally via Ollama, free, or the Claude API as a paid option) to take a first pass at huge lists of recon URLs and flag the most interesting ones to investigate manually during a bug bounty engagement.

It doesn't replace manual testing: it just helps you decide **where to start looking** among thousands of URLs.

## What it does

- Cleans up the URL list (drops static assets like images/CSS/fonts, deduplicates while ignoring tracking parameters like `utm_source`/`fbclid`)
- Prioritizes the most "interesting" URLs using keywords (`api`, `admin`, `debug`, `id=`, `.git`, etc.) and, when available, HTTP status code/content-type
- Splits the work into batches to avoid overflowing the model's context window
- Sends each batch to the model asking for the most critical candidates, in JSON format
- Saves a report in both JSON and readable Markdown, grouped by priority
- Keeps a **persistent checklist** per target, with a status (`to_test` / `confirmed` / `false_positive`) that's never lost between runs
- Lets you re-run the analysis on a new recon dump while only analyzing **new URLs** compared to last time (`--diff-only`)
- Automatically retries failed batches, and can resume a run that was interrupted midway

## Requirements

- Python 3.9 or higher
- [Ollama](https://ollama.com) installed and running (`ollama serve`), with at least one model pulled
- The `requests` library:

```
pip install requests
```

(`requests` is probably already installed on your system; if not, use `pip3 install requests --break-system-packages` on macOS with the system Python)

## Recommended models

The script defaults to `llama3`, but for this kind of task (classification/structured JSON output) models built specifically for function calling/JSON tend to do better:

```
ollama pull qwen2.5:7b
ollama pull hermes2-pro
```

Then use them with `--model qwen2.5:7b` (double-check with `ollama list` what the exact tag of your downloaded model actually is).

## Basic usage

```
python3 recoon.py URLS.txt --target "example.com" --domain-filter "example.com"
```

- `URLS.txt`: a file with one URL per line (or httpx-style JSON-lines output, or `-` to read from stdin)
- `--target`: the program/target name, used in the prompt and to keep state files separate between different projects — **always use the same string for the same program**
- `--domain-filter`: keeps only URLs containing this string (useful if the file mixes URLs from multiple domains)

When it's done you'll find two files in the current folder: `recon_report_<timestamp>.json` (full data) and `recon_report_<timestamp>.md` (readable, with checkboxes and grouped by priority).

## Updating the findings checklist

Every finding the model reports gets added to the target's persistent checklist with status `to_test`. To update it manually after you've verified it:

```
python3 recoon.py --target "example.com" --set-status "https://example.com/api/v1/orders?id=2" confirmed
```

Valid statuses: `to_test`, `confirmed`, `false_positive`. You can pass multiple `--set-status` in the same command. This command doesn't need a URL file: it only updates the checklist and exits.

In the Markdown report, each finding's status is shown as a checkbox/label — but it's display-only: checking the box in the `.md` file doesn't update anything, you always need `--set-status` (or editing the JSON by hand).

## Analyzing only what's new (`--diff-only`)

When you do a new recon pass and have an updated URL file, you can skip re-analyzing everything from scratch:

```
python3 recoon.py NEW_URLS.txt --target "example.com" --domain-filter "example.com" --diff-only
```

The script remembers which URLs it has already seen for that target and only analyzes the new ones. Important: always use the same `--target` for the same program, otherwise the comparison won't work.

## Generated files and organization

```
.recon_state/
└── example.com/
    ├── findings.json     # persistent checklist, survives every run
    └── seen_urls.json    # already-analyzed URLs, used by --diff-only
recon_report_<timestamp>.json
recon_report_<timestamp>.md
```

The `.recon_state/<target>/` folder is created automatically on first use, one per `--target` value: different programs never mix, even when running the script from the same working directory. Timestamped reports, on the other hand, stay in whichever folder you run the command from — if you're tracking multiple programs, a separate working folder per program (which you're probably already doing) is still a good idea.

## Using the Claude API instead of Ollama (optional)

By default everything stays local and free. If you want to use the Claude API instead of Ollama (e.g. Ollama isn't available, or you want a quality comparison on a subset):

```
export ANTHROPIC_API_KEY="sk-ant-..."
python3 recoon.py URLS.txt --target "example.com" --provider claude
```

Without specifying `--model` it will use `claude-haiku-4-5-20251001` (the cheapest one). API usage is paid and billed per token: for an analysis of a few hundred URLs the typical cost is a few cents of a dollar, but it's still a cost, unlike Ollama.

## Main options

| Option | Description | Default |
|---|---|---|
| `--target` | Program/target name | `target` |
| `--domain-filter` | Keep only URLs containing this string | none |
| `--provider` | `ollama` or `claude` | `ollama` |
| `--model` | Model name | `llama3` (Ollama) / `claude-haiku-4-5-20251001` (Claude) |
| `--top` | Maximum number of URLs to analyze | `150` |
| `--batch-size` | URLs per request to the model | `50` |
| `--temperature` | How "creative" the model is (lower = more stable) | `0.1` |
| `--seed` | Fixed seed for more reproducible results (Ollama only) | none |
| `--diff-only` | Only analyze URLs new since the last run | off |
| `--resume` | Resume an interrupted run | off |
| `--set-status URL STATUS` | Update a finding's status and exit | — |
| `--output` / `--markdown-output` | Custom report paths | automatic timestamp |

For the full list: `python3 recoon.py -h`

## Things to keep in mind

The model only judges based on the URL text (and status/content-type when available): it doesn't actively test anything. Every finding it reports is a hypothesis to verify by hand, not a confirmed vulnerability. Always check the program's scope and rules on Intigriti before actively testing anything.
