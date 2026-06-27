# KEA PGCET Monitor

This repository contains a production-ready Python monitor for the KEA PGCET announcements page:

`https://cetonline.karnataka.gov.in/kea/pgcet2026`

It scrapes the announcements section, compares the current page against the previously saved state, and sends Telegram alerts when it detects new or changed announcements.

## Repository layout

- [`tracker.py`](./tracker.py) - scraper, diff engine, Telegram notifier, and git persistence logic
- [`requirements.txt`](./requirements.txt) - Python dependencies for the runner
- [`known_announcements.json`](./known_announcements.json) - persisted announcement state used for change detection
- [`.github/workflows/monitor.yml`](./.github/workflows/monitor.yml) - GitHub Actions schedule and manual run workflow

## Secrets and environment variables

The script reads these values from environment variables:

- `BOT_TOKEN` - Telegram bot token
- `CHAT_ID` - Telegram chat ID
- `REQUESTS_PROXY` - optional proxy URL for routing KEA traffic through an allowed egress point

Do not hardcode either value in the repository.

## How it works

1. GitHub Actions runs the workflow every hour and also on manual dispatch.
2. `tracker.py` fetches the KEA PGCET page with retries, timeouts, and a browser-like user agent.
3. The scraper locates the `div.card-deck.shadow` announcements area and recursively extracts individual announcement blocks, visible text, links, PDF URLs, and dates when present.
4. The current snapshot is hashed and compared with `known_announcements.json`.
5. New or modified announcements trigger Telegram messages.
6. The updated state file is committed and pushed back to the repository so the next run knows what has already been seen.

If the site only responds from India, the cleanest option is to move the workflow onto a self-hosted runner in India.
Set the repository variable `MONITOR_RUNS_ON_JSON` to a JSON array of runner labels, for example:

```text
["self-hosted","linux","india"]
```

The monitor already supports `REQUESTS_PROXY` for environments where an outbound proxy is legitimately required.

## First run behavior

On the first successful run, the workflow sends this startup message:

```text
✅ KEA Monitor Running

Monitoring:
https://cetonline.karnataka.gov.in/kea/pgcet2026
```

After that, subsequent runs only notify on real changes.

## GitHub Actions setup

The workflow expects the repository to allow the default `GITHUB_TOKEN` to push commits back to the repo. The workflow file already requests `contents: write`.

## Local execution

Install dependencies and run the tracker:

```bash
pip install -r requirements.txt
python tracker.py
```

If `BOT_TOKEN` and `CHAT_ID` are not set, the script will still scrape and update state, but it will skip Telegram delivery.

If `REQUESTS_PROXY` is set, the scraper will route its outbound KEA request through that proxy.

## Notes on persistence

`known_announcements.json` stores the full structured snapshot, including:

- title
- URL
- date
- visible text
- all discovered links
- PDF URLs
- a stable identity hash

This lets the monitor detect:

- new announcements
- new links
- new PDFs
- modified text
- replaced PDFs
- changed URLs

## Deployment

Commit these files to the root of your existing repository. GitHub Actions will handle the hourly monitoring once the workflow is enabled.
