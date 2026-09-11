# grabu

It pulls every URL the Wayback Machine has indexed for a big list of subdomains, with optional Common Crawl support.

Built this for recon on big scopes. Give it a few hundred subdomains, let it run, and come back to a deduped URL list with the boring static asset noise filtered out and the interesting looking stuff flagged into its own file.

## Why does this exist??

Wayback's CDX API is genuinely great for this, but it starts refusing connections if you hammer it with too many threads. Most of the "waybackurls but threaded" scripts I found either ignore that and fall over on big lists, or run single threaded and take forever.

grabu handles the pacing, retries failed requests, and writes results as it goes. If it dies halfway through a big run, you don't lose everything it already collected.

## Install

```bash
pip install requests
```

## Usage

Run it with no arguments and it'll ask you what it needs.

```bash
python3 grabu.py
```

Or skip the prompts. Here is an example.

```bash
python3 grabu.py -f subdomains.txt -o combined.txt -t 20 --rps 2
```

## flags

| flag            | what it does                                       | default        |
| --------------- | -------------------------------------------------- | -------------- |
| `-f, --file`    | txt file, one subdomain per line                   | required       |
| `-o, --output`  | where the URLs get written                         | `combined.txt` |
| `-t, --threads` | worker threads                                     | `20`           |
| `--rps`         | max requests/sec per source, shared across threads | `2.0`          |
| `--concurrency` | max requests in flight per source                  | `5`            |
| `--timeout`     | per-request timeout in seconds                     | `20`           |
| `-s, --source`  | `wayback`, `commoncrawl`, or `all`                 | `wayback`      |
| `--no-filter`   | keep everything, including images/css/fonts/media  | off            |
| `-v, --verbose` | print every request as it happens                  | off            |

Run `python3 grabu.py -h` for the full descriptions.

## sources

**Wayback** is the main one. It has the best coverage by far, so that's what you'll probably use most of the time.

**Common Crawl** is there as a backup. Its coverage is patchier, especially for obscure subdomains, but running `-s all` merges both sources into one output.

I considered adding urlscan and AlienVault OTX too, but they don't really do the same thing. OTX is threat intel indicators, not a general URL archive, and urlscan depends on domains someone happened to scan. Didn't seem worth adding more complexity.

## What you get

If you run it with `-o combined.txt`, you'll get:

* **`combined.txt`** — every unique URL found, with noise filtered out.
* **`combined.interesting.txt`** — URLs that match things like `.env`, `.sql`, `.bak`, `.git/`, `.pem`, `wp-config`, `.aws`, backup files, exposed configs, and similar paths.
* **`combined.txt.failed`** — only created if some subdomains still failed after the slower retry pass.

The interesting file is just a filter based on the URL. It doesn't mean anything is actually exposed or vulnerable. You'll still have to check what you find.

Ctrl+C also saves everything gathered so far before exiting.

## A heads up on scale

With the default `--rps 2` and a few thousand subdomains, this is going to take a while. That's deliberate. Wayback starts getting unhappy when you push it too hard.

You can bump `--rps` if you want, but if you start getting connection errors, turn it back down. The default is there for a reason.
