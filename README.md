# Forensic Timeline Engine

Python tool for IT 360 that reads AWS CloudTrail, Office 365 and Google Workspace logs, merges them into one UTC timeline, has an AI model flag suspicious activity, and writes an HTML report.

## Features

- Reads AWS CloudTrail, Office 365 and Google Workspace logs. It figures out the type from the file, so you never say which one it is.
- Converts every time to UTC and merges all events into one sorted timeline with IDs (E0001, E0002, ...).
- Takes a SHA-256 hash of each input file before reading it and puts it in the report.
- Sends the timeline to an Ollama model in overlapping chunks and gets back findings with a risk score, anomaly type, confidence and the event IDs behind each one.
- Checks every AI finding with code. Cited event IDs have to exist and any IP in a finding has to be in the events it cites. Findings that fail are kept and marked NOT verified.
- Writes a standalone HTML report with the evidence hashes, affected accounts, IPs, findings grouped by severity and the full timeline. Every log value is escaped.
- Writes a review sheet and a scoring script for the manual accuracy check (target is 70%).

## Setup

Needs Python 3.11 or newer.

```
git clone https://github.com/jclapp04/IT360-Project.git
cd IT360-Project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The timeline and report work with just that. The AI step (`--ai`) also needs a `config.py` with the Ollama server details:

```
cp config_example.py config.py
nano config.py           # set OLLAMA_HOST, OLLAMA_API_KEY and OLLAMA_MODEL
python3 check_ollama.py  # should print a short reply from the model
```

## Usage

```
python3 main.py                     # reads every file in samples/
python3 main.py aws.json o365.json  # or name the files
python3 main.py --ai                # adds the AI analysis and review sheet
python3 main.py --ai --open         # also opens the report in the browser
python3 score.py                    # scores the newest review sheet
```

Each run writes files that share one UTC timestamp, so old results never get overwritten.

| File | What it is |
|---|---|
| `timeline_<time>.csv` | the merged timeline |
| `report_<time>.html` | the report, open it in a browser |
| `ai_<time>.json` | the AI results and the check result for each finding (only with `--ai`) |
| `review_<time>.csv` | one row per AI finding for the manual review (only with `--ai`) |

These are all in `.gitignore`.

## How it works

```
log files -> SHA-256 hash -> reader for each format -> UTC events
          -> merge, sort, IDs -> timeline.csv
          -> AI chunks -> checks on each finding -> ai.json and review sheet
          -> report.html
```

1. `main.py` hashes each file. `fte/readers/` figures out the format and turns every record into an `Event` (time, source, action, user, IP, target, outcome, detail).
2. `fte/timeline.py` sorts all events by UTC time and numbers them.
3. `fte/summarize.py` splits the timeline into groups of 40 events (10 shared with the next group so a suspicious sequence isn't cut in half), sends each one to the model with strict instructions, and reads the JSON that comes back.
4. Each finding is checked against the real events, then `fte/report.py` builds the report.

The model runs at temperature 0 so the same timeline gives nearly the same answer each time. The API call is in `fte/ollama_client.py`.

## Accuracy check

1. Run `python3 main.py --ai`, then open `review_<time>.csv`.
2. For each finding, compare the statement to the events it cites and type `correct`, `partial` or `incorrect` in the last column. Review the NOT verified ones too.
3. Run `python3 score.py`. It prints the score with only correct counted and with partial counted as half.

Verified in the report only means the automatic checks passed. It doesn't mean the finding is right, which is what the manual review decides.

## Limitations

- The checks catch made up event IDs and IPs but not other wrong claims.
- Office 365 times have no time zone, so they are treated as UTC. An export in local time would end up in the wrong spot.
- The same person can show up under different names in different logs (`test.user` in AWS and `test.user@corp.example` in Office 365). The report lists them as separate accounts.
- Log text can be controlled by an attacker. The prompt tells the model to treat it as data and the report escapes every value, but a model can still be influenced by what is in a log.
- The files in `samples/` are small made up examples, not real incident data.
- Only JSON input works and the report is a static page with no filters.
- The tool only reads and reports. It doesn't block or change anything.

## Project layout

```
main.py                 run this
score.py                scores the manual review
check_ollama.py         tests the connection to the Ollama server
check_ai.py             runs just the AI step and prints the raw result
config_example.py       template for config.py (config.py itself isn't committed)
requirements.txt        Python packages (requests, pytest)
fte/models.py           the Event structure
fte/util.py             time and IP helpers
fte/evidence.py         SHA-256 hashing
fte/readers/            one reader per log type and the format detection
fte/timeline.py         merges, sorts and numbers events
fte/ollama_client.py    API call to the Ollama server
fte/summarize.py        prompt, chunking and checks on AI findings
fte/report.py           HTML report
fte/evaluate.py         review sheet
samples/                small example logs
```
