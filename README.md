# grabu

It pulls every URL Wayback Machine (and optionally common crawl) has ever archived for a big list of subdomains. It's threaded & rate-limited so it doesn't get you blocked, resumable if you Ctrl+C out of it, and it actually tries to tell you what's worth looking at instead of just dumping 200k urls in your lap.

Built this because every "Waybackurls but threaded" script either falls over on a big scope or runs single threaded and takes forever. this one paces itself, speeds up on its own when the archive's behaving, and doesn't lose progress if it dies halfway.

## Install

```
pip install requests
```

## Usage

no args, and it walks you through it.

```
python3 grabu.py
```

It validates your file as you type the path, shows you a summary of exactly what's about to run (subdomains found, rough time estimate, which files you'll get) before anything actually starts, and gives you the equivalent one liner at the end so you can skip the questions next time.

or just skip straight to the flags.

```
python3 grabu.py -f subdomains.txt -o combined.txt -t 20 --rps 2 -s wayback
```

## Flags

| flag | what it does | default |
|---|---|---|
| `-f, --file` | txt file, one subdomain per line | required |
| `-o, --output` | where the urls get written | `combined.txt` |
| `-t, --threads` | worker threads pulling from the queue | `20` |
| `--rps` | starting requests/sec per source — this ramps up on its own | `2.0` |
| `--max-rps` | ceiling the auto rate limiter won't cross | `8.0` |
| `--concurrency` | max requests in flight at once per source (commoncrawl force-capped at 2, it just can't take more) | `5` |
| `--cc-indexes` | how many recent commoncrawl monthly snapshots to check, `0` = all of them (slow) | `6` |
| `--timeout` | per-request timeout in seconds | `20` |
| `-s, --source` | `wayback`, `commoncrawl`, or `all` | `wayback` |
| `--no-filter` | keep everything, including images/css/fonts | off |
| `--dedupe-paths` | collapse `?id=1`, `?id=2`, `?id=3`... into one — never touches anything flagged interesting | off |
| `--jsonl` | also write `<output>.jsonl` with url/mimetype/status/timestamp/subdomain per record | off |
| `-r, --report` | write a markdown writeup to `<output>.report.md` | off |
| `--recheck` | after the run, actually ping the interesting urls to see if they still respond today | off |
| `--dry-run` | show subdomain count + time estimate, exit without sending a single request | off |
| `-v, --verbose` | print every request as it fires and lands | off |
| `-q, --quiet` | periodic progress updates instead of one line per subdomain — good for huge lists | off |
| `--fresh` | ignore a previous partial run and start clean | off |

`python3 grabu.py -h` for the long version of all of these.

## What you actually get

- **`combined.txt`** — every unique url, static-asset noise already stripped out. filtering uses the real archived mimetype when available, not just a guess off the file extension, so a no-extension route that served json back in 2019 still gets caught
- **`combined.interesting.txt`** — the subset that's actually worth your time, grouped by severity when it prints to your terminal: an actual leaked key/token sitting in the url itself comes first, then credentials/keys, backups, configs, version control leftovers, docs, admin/debug stuff. each hit shows the year it was first archived if we know it
- **`combined.new.txt`** — only shows up if you've scanned this same output before. rerun grabu later and it'll tell you what's new since last time instead of making you diff two giant files yourself
- **`combined.params.txt`** — every unique query param name seen, ready to feed into ffuf or whatever
- **`combined.paths.txt`** — same idea but for path segments, a decent wordlist starting point
- **`combined.txt.failed`** — subdomains that never came back clean even after a slower retry pass. rerun grabu pointed at just this file later
- optional: `.jsonl` for structured output, `.report.md` for an actual writeup, `.live.txt` if you used `--recheck` to see which findings still respond today

hit Ctrl+C any time and it saves what it's gathered before exiting. rerun the same command later and it picks up exactly where it left off, already-done subdomains get skipped, nothing already in `combined.txt` gets lost or overwritten.

## A heads up on scale

Start rps is just that, a starting point. it climbs on its own when requests are landing clean and instantly cuts itself in half the moment something errors out, so you don't have to guess a number. that said, wayback still has a real ceiling somewhere around 8-10 req/sec no matter how patient you are, so a few thousand subdomains is still going to take a while. that's the archive being the archive, not a bug here.

`--recheck` sends actual live requests to the current hosts, not the archive, worth knowing that distinction before you run it against something you don't have explicit scope on.

one thing i haven't gotten around to, wayback's cdx api can theoretically paginate on subdomains with a truly massive capture history, and this doesn't follow resume keys. unlikely to bite you on a random subdomain, more likely on something like a root domain with millions of captures. flag it if you hit it.
