import argparse
import concurrent.futures
import json
import os
import posixpath
import re
import signal
import sys
import threading
import time
from collections import Counter, defaultdict
from urllib.parse import urlparse, parse_qs

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

sources_avail = ["wayback", "commoncrawl"]

noise_ext = {
    "jpg", "jpeg", "png", "gif", "svg", "ico", "webp", "bmp", "tiff", "tif", "avif",
    "woff", "woff2", "ttf", "eot", "otf",
    "css",
    "mp4", "mp3", "avi", "mov", "wav", "webm", "ogg", "flv", "m4a", "m4v", "mkv", "swf",
}

hot_ext = {
    "env", "git", "sql", "db", "sqlite", "sqlite3", "bak", "backup", "old", "orig",
    "zip", "tar", "gz", "tgz", "rar", "7z", "pem", "key", "pfx", "p12", "crt",
    "log", "yml", "yaml", "conf", "config", "ini", "properties",
    "json", "xml", "csv", "doc", "docx", "xls", "xlsx", "pdf", "dump", "sh", "ps1",
}

hot_kw = [
    "wp-config", "htaccess", "htpasswd", "phpinfo", "web.config", "docker-compose",
    ".aws", "id_rsa", ".npmrc", ".pypirc", ".ssh", "credential", "password", "secret",
    "token", "apikey", "api_key", "backup", "dump", "swagger", "api-docs", "actuator",
    ".well-known", "/private/", "/internal/", ".git/", ".svn/", ".ds_store",
    "config.php", "settings.py",
]

noise_mime_pfx = ("image/", "font/", "video/", "audio/")
noise_mime_eq = {"text/css"}

hot_mime = {
    "application/json", "application/xml", "text/xml", "text/plain",
    "application/x-yaml", "text/yaml", "application/x-sql", "application/octet-stream",
    "application/zip", "application/x-tar", "application/gzip", "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

severity = [
    "secrets-in-url",
    "credentials/keys",
    "backup/dump",
    "config/env",
    "version control",
    "docs/data",
    "admin/debug",
    "other",
]

secret_patterns = [
    ("aws access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

buckets = [
    (
        "credentials/keys",
        {"pem", "key", "pfx", "p12", "crt"},
        ["id_rsa", ".aws", ".ssh", ".npmrc", ".pypirc", "credential", "password", "secret", "token", "apikey", "api_key"],
    ),
    (
        "backup/dump",
        {"bak", "backup", "old", "orig", "dump", "sql", "db", "sqlite", "sqlite3", "zip", "tar", "gz", "tgz", "rar", "7z"},
        ["backup", "dump"],
    ),
    (
        "config/env",
        {"env", "yml", "yaml", "conf", "config", "ini", "properties"},
        ["wp-config", "htaccess", "htpasswd", "web.config", "docker-compose", "config.php", "settings.py"],
    ),
    (
        "version control",
        set(),
        [".git/", ".svn/", ".ds_store"],
    ),
    (
        "docs/data",
        {"doc", "docx", "xls", "xlsx", "pdf", "csv", "json", "xml", "log"},
        [],
    ),
    (
        "admin/debug",
        set(),
        ["phpinfo", "swagger", "api-docs", "actuator", ".well-known"],
    ),
]


def url_ext(u):
    path = urlparse(u).path
    name = path.rsplit("/", 1)[-1]

    if name.startswith(".") and name.count(".") == 1:
        return name[1:].lower()

    return posixpath.splitext(path)[1].lstrip(".").lower()


def clean_mime(mime):
    if not mime or mime in ("-", "unk", "warc/revisit"):
        return None

    return mime.lower()


def is_noise(u, mime=None):
    m = clean_mime(mime)

    if m and (m in noise_mime_eq or m.startswith(noise_mime_pfx)):
        return True

    return url_ext(u) in noise_ext


def secret_in(u):
    for name, rx in secret_patterns:
        if rx.search(u):
            return name

    return None


def is_hot(u, mime=None):
    if secret_in(u):
        return True

    m = clean_mime(mime)

    if m and m in hot_mime:
        return True

    if url_ext(u) in hot_ext:
        return True

    low = u.lower()

    return any(k in low for k in hot_kw)


def bucket_of(u):
    if secret_in(u):
        return "secrets-in-url"

    ext = url_ext(u)
    low = u.lower()

    for name, exts, kws in buckets:
        if ext in exts or any(k in low for k in kws):
            return name

    return "other"


def year_of(ts):
    if ts and len(ts) >= 4 and ts[:4].isdigit():
        return int(ts[:4])

    return None


def path_key(u):
    p = urlparse(u)
    params = tuple(sorted(parse_qs(p.query).keys()))

    return (p.netloc, p.path, params)


def params_of(u):
    q = urlparse(u).query

    return list(parse_qs(q).keys()) if q else []


def segments_of(u):
    return [seg for seg in urlparse(u).path.split("/") if seg]


def clean_sub(line):
    s = line.strip()

    if not s or s.startswith("#"):
        return None

    if "://" in s:
        s = s.split("://", 1)[1]

    s = s.split("/", 1)[0].split("?", 1)[0]

    return s.strip().rstrip(".").lower() or None


class RateLimiter:
    def __init__(self, start, floor, ceiling):
        self.rps = start
        self.floor = floor
        self.ceiling = ceiling
        self.lock = threading.Lock()
        self.next_time = 0.0

    def wait(self):
        with self.lock:
            interval = 1.0 / self.rps
            now = time.monotonic()
            sleep_for = max(0.0, self.next_time - now)
            self.next_time = max(now, self.next_time) + interval

        if sleep_for > 0:
            time.sleep(sleep_for)

    def success(self):
        with self.lock:
            self.rps = min(self.ceiling, self.rps + 0.15)

    def failure(self):
        with self.lock:
            self.rps = max(self.floor, self.rps / 2)


def new_session():
    s = requests.Session()

    retry = Retry(
        total=5,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
        respect_retry_after_header=True,
    )

    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update({"User-Agent": "Mozilla/5.0 (compatible; grabu/1.0)"})

    return s


def split_line(line):
    p = line.split()

    u = p[0] if len(p) > 0 else None
    mime = p[1] if len(p) > 1 else None
    status = p[2] if len(p) > 2 else None
    ts = p[3] if len(p) > 3 else None

    return u, mime, status, ts


def fetch_wayback(sub, session, timeout):
    params = {
        "url": f"{sub}/*",
        "output": "text",
        "fl": "original,mimetype,statuscode,timestamp",
        "collapse": "urlkey",
    }

    r = session.get(
        "https://web.archive.org/cdx/search/cdx",
        params=params,
        timeout=timeout,
    )

    r.raise_for_status()

    out = []

    for line in r.text.splitlines():
        line = line.strip()

        if not line:
            continue

        u, mime, status, ts = split_line(line)

        if u:
            out.append((u, mime, status, ts))

    return out


def cc_sort_key(entry):
    parts = entry.get("id", "").split("-")

    try:
        return int(parts[2]), int(parts[3])
    except (IndexError, ValueError):
        return 0, 0


def cc_list(session, timeout, count):
    r = session.get(
        "https://index.commoncrawl.org/collinfo.json",
        timeout=timeout,
    )

    r.raise_for_status()

    data = sorted(r.json(), key=cc_sort_key, reverse=True)
    apis = [c["cdx-api"] for c in data]

    if count > 0:
        apis = apis[:count]

    return apis


def fetch_commoncrawl(sub, session, timeout, cc_api):
    params = {
        "url": f"{sub}/*",
        "output": "json",
    }

    r = session.get(cc_api, params=params, timeout=timeout)

    if r.status_code == 404:
        return []

    r.raise_for_status()

    out = []

    for line in r.text.splitlines():
        line = line.strip()

        if not line:
            continue

        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        u = rec.get("url")

        if u:
            out.append((
                u,
                rec.get("mime"),
                rec.get("status"),
                rec.get("timestamp"),
            ))

    return out


def hit(fn, sub, session, timeout, lim, sem, verbose, label):
    lim.wait()
    sem.acquire()

    start = time.monotonic()

    if verbose:
        print(f"    -> {label} requesting {sub}", flush=True)

    try:
        got = fn(sub, session, timeout)
        lim.success()

        if verbose:
            print(
                f"    <- {label} {sub}: {len(got)} urls in {time.monotonic() - start:.1f}s",
                flush=True,
            )

        return got, None

    except Exception as e:
        lim.failure()

        if verbose:
            print(
                f"    <- {label} {sub}: failed after {time.monotonic() - start:.1f}s ({e})",
                flush=True,
            )

        return [], str(e)

    finally:
        sem.release()


def fetch(
    sub,
    session,
    timeout,
    limiters,
    semaphores,
    sources,
    cc_indexes,
    verbose=False,
):
    urls = []
    errors = []

    for src in sources:
        if src == "wayback":
            got, err = hit(
                fetch_wayback,
                sub,
                session,
                timeout,
                limiters[src],
                semaphores[src],
                verbose,
                "wayback",
            )

            urls.extend(got)

            if err:
                errors.append(f"wayback: {err}")

        elif src == "commoncrawl":
            ok = 0

            for idx in cc_indexes:
                fn = lambda s, ses, t, idx=idx: fetch_commoncrawl(s, ses, t, idx)

                got, err = hit(
                    fn,
                    sub,
                    session,
                    timeout,
                    limiters[src],
                    semaphores[src],
                    verbose,
                    "commoncrawl",
                )

                urls.extend(got)

                if err is None:
                    ok += 1

            if cc_indexes and ok == 0:
                errors.append(
                    f"commoncrawl: all {len(cc_indexes)} indexes failed"
                )

    return sub, urls, "; ".join(errors) if errors else None


def ping(u, session, timeout):
    try:
        r = session.head(
            u,
            timeout=timeout,
            allow_redirects=True,
        )

        if r.status_code >= 400:
            r = session.get(
                u,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
            )

        return u, r.status_code

    except Exception:
        return u, None


def paint(text, code, use_color):
    return f"\033[{code}m{text}\033[0m" if use_color else text


def prompt(msg, default=""):
    v = input(
        f"{msg} [{default}]: " if default else f"{msg}: "
    ).strip()

    return v or default


presets = {
    "1": {
        "threads": 15,
        "rps": 1.5,
        "max_rps": 4.0,
        "concurrency": 3,
        "label": "safe",
    },
    "2": {
        "threads": 20,
        "rps": 2.5,
        "max_rps": 8.0,
        "concurrency": 5,
        "label": "balanced",
    },
    "3": {
        "threads": 30,
        "rps": 4.0,
        "max_rps": 15.0,
        "concurrency": 8,
        "label": "fast",
    },
}


def ask_file():
    while True:
        path = prompt("path to your subdomains file")

        if not path:
            continue

        if not os.path.exists(path):
            print(f"  can't find '{path}' — check the path and try again")
            continue

        try:
            with open(path) as f:
                count = len(set(
                    filter(None, (clean_sub(l) for l in f))
                ))

        except Exception as e:
            print(f"  couldn't read that file: {e}")
            continue

        if count == 0:
            print("  that file doesn't have any subdomains in it")
            continue

        print(f"  found {count} subdomains")

        return path, count


def est_reqs(source, cc_indexes):
    n = cc_indexes if cc_indexes > 0 else 40

    if source == "wayback":
        return 1

    if source == "commoncrawl":
        return n

    return 1 + n


def equiv_cmd(a):
    parts = [
        "python3 grabu.py",
        f"-f {a.file}",
        f"-o {a.output}",
        f"--outdir {a.outdir}",
        f"-t {a.threads}",
        f"--rps {a.rps}",
        f"--max-rps {a.max_rps}",
        f"--concurrency {a.concurrency}",
        f"-s {a.source}",
    ]

    if a.source != "wayback":
        parts.append(f"--cc-indexes {a.cc_indexes}")

    if a.dedupe_paths:
        parts.append("--dedupe-paths")

    if a.no_filter:
        parts.append("--no-filter")

    if a.quiet:
        parts.append("--quiet")

    if a.verbose:
        parts.append("-v")

    return " ".join(parts)


def wizard():
    banner = """
░██████╗░██████╗░░█████╗░██████╗░██╗░░░██╗
██╔════╝░██╔══██╗██╔══██╗██╔══██╗██║░░░██║
██║░░██╗░██████╔╝███████║██████╦╝██║░░░██║
██║░░╚██╗██╔══██╗██╔══██║██╔══██╗██║░░░██║
╚██████╔╝██║░░██║██║░░██║██████╦╝╚██████╔╝
░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░░╚═════╝░
"""
    print(banner)

    file, count = ask_file()

    output_dir = prompt("name for the results directory", "results")
    output = prompt("name for the output file", "combined.txt")

    print("\nhow fast should this run?")
    print("  1) safe     - slower, very unlikely to get temporarily blocked (recommended)")
    print("  2) balanced - a bit faster, small risk of getting slowed down")
    print("  3) fast     - quickest, higher chance the archive briefly blocks you")

    speed = prompt("pick one", "1")
    cfg = dict(presets.get(speed, presets["1"]))

    cc_indexes = 6

    cc = prompt(
        "also check common crawl as a backup source? roughly doubles run time (y/n)",
        "n",
    )

    source = "all" if cc.lower().startswith("y") else "wayback"

    collapse = prompt(
        "collapse near-duplicate urls that only differ by an id/number? (y/n)",
        "y",
    )

    filt = prompt(
        "filter out boring static files like images/css/fonts? (y/n)",
        "y",
    )

    print("\nhow much do you want printed while this runs?")
    print("  1) one line per subdomain (recommended)")
    print("  2) just periodic progress updates - easier to read on a huge list")
    print("  3) everything, every single request (for debugging)")

    out_mode = prompt("pick one", "1" if count < 300 else "2")

    quiet = out_mode == "2"
    verbose = out_mode == "3"

    tweak = prompt(
        "\nfine-tune the raw technical settings instead of using the preset? (y/n)",
        "n",
    )

    if tweak.lower().startswith("y"):
        cfg["threads"] = int(prompt("threads", str(cfg["threads"])))
        cfg["rps"] = float(prompt("starting requests/sec per source", str(cfg["rps"])))
        cfg["max_rps"] = float(prompt("max requests/sec per source", str(cfg["max_rps"])))
        cfg["concurrency"] = int(prompt("max simultaneous requests per source", str(cfg["concurrency"])))

        if source != "wayback":
            cc_indexes = int(
                prompt(
                    "commoncrawl monthly indexes to check, 0 = all",
                    str(cc_indexes),
                )
            )

    args = argparse.Namespace(
        file=file,
        output=output,
        outdir=output_dir,
        threads=cfg["threads"],
        timeout=20,
        rps=cfg["rps"],
        max_rps=cfg["max_rps"],
        concurrency=cfg["concurrency"],
        cc_indexes=cc_indexes,
        no_filter=not filt.lower().startswith("y"),
        source=source,
        verbose=verbose,
        quiet=quiet,
        fresh=False,
        dedupe_paths=collapse.lower().startswith("y"),
        jsonl=False,
        report=False,
        recheck=False,
        dry_run=False,
    )

    reqs = count * est_reqs(source, cc_indexes)
    best = reqs / cfg["max_rps"] / 60
    worst = reqs / cfg["rps"] / 60

    stem, ext = posixpath.splitext(output)

    print("\nhere's what's about to run:")
    print(f"  {count} subdomains from {file}")
    print(f"  results directory: {output_dir}")
    print(f"  speed: {cfg['label']}, sources: {source}")
    print(f"  rough estimate: {best:.0f}-{worst:.0f} minutes (usually closer to the low end once it ramps up)")

    print("\nfiles you'll get:")
    print(f"  {output}            every url found")
    print(f"  {stem}.interesting.txt   the subset worth checking first")
    print(f"  {stem}.params.txt       unique query param names, good fuzzing wordlist")
    print(f"  {stem}.paths.txt        unique path segments")

    print("\npower-user extras not asked here, see -h: --jsonl --report --recheck")

    print("\nequivalent command, if you want to skip this next time:")
    print(f"  {equiv_cmd(args)}")

    go = prompt("\nstart now? (y/n)", "y")

    if not go.lower().startswith("y"):
        print("no changes made, run me again when you're ready")
        sys.exit(0)

    print()

    return args


def parse_args():
    p = argparse.ArgumentParser(
        description="grab all indexed urls for a list of subdomains from wayback machine and common crawl",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "example: python3 grabu.py -f subs.txt -o combined.txt --outdir results -t 20 --rps 2 -s wayback\n"
            "tip: run with no arguments at all (just `python3 grabu.py`) for a guided setup instead of flags"
        ),
    )

    p.add_argument(
        "-f",
        "--file",
        required=True,
        help="txt file with one subdomain per line",
    )

    p.add_argument(
        "-o",
        "--output",
        default="combined.txt",
        help="name of the main output file",
    )

    p.add_argument(
        "--outdir",
        default="results",
        help="directory where all output files get saved",
    )

    p.add_argument(
        "-t",
        "--threads",
        type=int,
        default=20,
        help="worker threads pulling from the queue",
    )

    p.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="per-request timeout in seconds",
    )

    p.add_argument(
        "--rps",
        type=float,
        default=2.0,
        help="starting requests/sec per source, ramps up automatically when things are going well",
    )

    p.add_argument(
        "--max-rps",
        type=float,
        default=8.0,
        help="ceiling the adaptive rate limiter won't cross",
    )

    p.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="max simultaneous in-flight requests per source",
    )

    p.add_argument(
        "--cc-indexes",
        type=int,
        default=6,
        help="how many recent commoncrawl monthly snapshots to check per subdomain, 0 = every snapshot ever",
    )

    p.add_argument(
        "-s",
        "--source",
        choices=sources_avail + ["all"],
        default="wayback",
        help="wayback, commoncrawl, or all",
    )

    p.add_argument(
        "--no-filter",
        action="store_true",
        help="disable noise filtering",
    )

    p.add_argument(
        "--dedupe-paths",
        action="store_true",
        help="collapse urls that share the same path and param names",
    )

    p.add_argument(
        "--jsonl",
        action="store_true",
        help="also write a JSONL file with url/mimetype/statuscode/subdomain per line",
    )

    p.add_argument(
        "-r",
        "--report",
        action="store_true",
        help="write a markdown summary",
    )

    p.add_argument(
        "--recheck",
        action="store_true",
        help="after the run, send live requests to interesting urls",
    )

    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print every request as it's sent and completed",
    )

    p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="only print periodic progress updates",
    )

    p.add_argument(
        "--fresh",
        action="store_true",
        help="ignore any previous partial run and start over",
    )

    p.add_argument(
        "--dry-run",
        action="store_true",
        help="show the subdomain count and estimate, then exit",
    )

    return p.parse_args()


def run(args):
    use_color = sys.stdout.isatty()

    sources = sources_avail if args.source == "all" else [args.source]

    os.makedirs(args.outdir, exist_ok=True)

    out_base = os.path.join(args.outdir, args.output)

    try:
        with open(args.file) as f:
            subs = sorted(set(
                filter(None, (clean_sub(l) for l in f))
            ))

    except FileNotFoundError:
        print(f"no such file: {args.file}")
        sys.exit(1)

    if not subs:
        print("no subdomains found in file")
        sys.exit(1)

    session = new_session()

    cc_indexes = []

    if "commoncrawl" in sources:
        try:
            cc_indexes = cc_list(
                session,
                args.timeout,
                args.cc_indexes,
            )

        except Exception as e:
            print(
                f"couldn't reach commoncrawl index, dropping it from this run: {e}",
                flush=True,
            )

            sources = [
                s for s in sources
                if s != "commoncrawl"
            ]

    if not sources:
        print("no usable sources left")
        sys.exit(1)

    done_path = out_base + ".done"

    done = set()

    resume = not args.fresh and os.path.exists(done_path)

    if resume:
        with open(done_path) as f:
            done = set(
                l.strip()
                for l in f
                if l.strip()
            )

        subs = [
            s for s in subs
            if s not in done
        ]

        print(
            f"resuming: {len(done)} already done, {len(subs)} left",
            flush=True,
        )

    if not subs:
        print(
            "nothing left to do, all subdomains already processed (use --fresh to start over)",
            flush=True,
        )

        sys.exit(0)

    print(
        f"{len(subs)} subdomains, sources: {','.join(sources)}, "
        f"{args.threads} threads, {args.rps}-{args.max_rps} req/s/source "
        f"(adaptive), writing to {out_base}",
        flush=True,
    )

    if args.dry_run:
        reqs = len(subs) * est_reqs(args.source, args.cc_indexes)

        best = reqs / args.max_rps / 60
        worst = reqs / args.rps / 60

        print(
            f"dry run — nothing sent. rough estimate: {best:.0f}-{worst:.0f} minutes",
            flush=True,
        )

        sys.exit(0)

    seen = set()

    if resume and os.path.exists(out_base):
        with open(out_base) as f:
            seen = set(
                l.strip()
                for l in f
                if l.strip()
            )

    dropped = 0
    collapsed = 0
    kept = len(seen)
    hot_count = 0
    min_year = None
    max_year = None

    params_seen = set()
    seg_seen = set()
    hot_urls = []
    new_hot = []

    bucket_counts = Counter()
    bucket_samples = defaultdict(list)

    lock = threading.Lock()

    mode = "a" if resume else "w"

    stem, ext = posixpath.splitext(args.output)
    stem = os.path.join(args.outdir, stem)

    hot_path = f"{stem}.interesting{ext or '.txt'}"

    prev_hot = set()

    if os.path.exists(hot_path):
        with open(hot_path) as f:
            prev_hot = set(
                l.strip()
                for l in f
                if l.strip()
            )

    out = open(out_base, mode, buffering=1)
    hot_out = open(hot_path, mode, buffering=1)
    done_out = open(done_path, mode, buffering=1)

    jsonl_out = (
        open(f"{stem}.jsonl", mode, buffering=1)
        if args.jsonl
        else None
    )

    key_seen = set()

    if resume and args.dedupe_paths:
        for u in seen:
            key_seen.add(path_key(u))

    limiters = {
        src: RateLimiter(
            args.rps,
            0.25,
            args.max_rps,
        )
        for src in sources
    }

    caps = {
        src: (
            min(args.concurrency, 2)
            if src == "commoncrawl"
            else args.concurrency
        )
        for src in sources
    }

    semaphores = {
        src: threading.Semaphore(caps[src])
        for src in sources
    }

    n = 0
    failed = []
    total = len(subs)

    show_every = (
        1
        if not args.quiet
        else max(1, total // 40)
    )

    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=args.threads
    )

    futures = {
        executor.submit(
            fetch,
            sub,
            session,
            args.timeout,
            limiters,
            semaphores,
            sources,
            cc_indexes,
            args.verbose,
        ): sub
        for sub in subs
    }

    def close_files():
        out.flush()
        out.close()

        hot_out.flush()
        hot_out.close()

        done_out.flush()
        done_out.close()

        if jsonl_out:
            jsonl_out.flush()
            jsonl_out.close()

    def bail():
        print(
            f"\nstopped, {kept} urls saved to {out_base} "
            f"({n}/{total} subdomains processed)",
            flush=True,
        )

        close_files()

        executor.shutdown(
            wait=False,
            cancel_futures=True,
        )

        sys.exit(0)

    signal.signal(signal.SIGINT, lambda sig, frame: bail())

    def record(sub, results):
        nonlocal dropped, collapsed, kept, hot_count, min_year, max_year

        new = 0

        with lock:
            for u, mime, status, ts in results:
                if u in seen:
                    continue

                seen.add(u)

                if not args.no_filter and is_noise(u, mime):
                    dropped += 1
                    continue

                hot = is_hot(u, mime)

                if args.dedupe_paths and not hot:
                    key = path_key(u)

                    if key in key_seen:
                        collapsed += 1
                        continue

                    key_seen.add(key)

                out.write(u + "\n")

                new += 1
                kept += 1

                params_seen.update(params_of(u))
                seg_seen.update(segments_of(u))

                yr = year_of(ts)

                if yr:
                    min_year = (
                        yr
                        if min_year is None
                        else min(min_year, yr)
                    )

                    max_year = (
                        yr
                        if max_year is None
                        else max(max_year, yr)
                    )

                if jsonl_out:
                    jsonl_out.write(
                        json.dumps({
                            "url": u,
                            "mime": mime,
                            "status": status,
                            "ts": ts,
                            "sub": sub,
                        }) + "\n"
                    )

                if hot:
                    hot_out.write(u + "\n")

                    hot_count += 1
                    hot_urls.append(u)

                    if u not in prev_hot:
                        new_hot.append(u)

                    b = bucket_of(u)

                    bucket_counts[b] += 1

                    if len(bucket_samples[b]) < 3:
                        bucket_samples[b].append((u, yr))

            done_out.write(sub + "\n")

        return new

    clock = time.monotonic()

    for fut in concurrent.futures.as_completed(futures):
        sub = futures[fut]

        _, results, err = fut.result()

        new = record(sub, results)

        n += 1

        if err:
            failed.append(sub)

        if err or n % show_every == 0 or n == total:
            rate = n / max(
                0.001,
                time.monotonic() - clock,
            )

            eta = (
                (total - n) / rate / 60
                if rate > 0
                else 0
            )

            status = (
                paint(f"err: {err}", "31", use_color)
                if err
                else f"{new} new"
            )

            print(
                f"[{n}/{total}] {sub} -> {status} "
                f"({kept} total, ~{eta:.0f}m left)",
                flush=True,
            )

    executor.shutdown(wait=True)

    if failed:
        print(
            f"\n{len(failed)} subdomains failed, retrying sequentially at a slower pace...",
            flush=True,
        )

        slow_limiters = {
            src: RateLimiter(
                max(0.25, args.rps / 4),
                0.1,
                args.max_rps / 2,
            )
            for src in sources
        }

        slow_semaphores = {
            src: threading.Semaphore(1)
            for src in sources
        }

        still_failed = []

        for i, sub in enumerate(failed, 1):
            _, results, err = fetch(
                sub,
                session,
                args.timeout,
                slow_limiters,
                slow_semaphores,
                sources,
                cc_indexes,
                args.verbose,
            )

            new = record(sub, results)

            if err:
                still_failed.append(sub)

            status = (
                paint(f"err: {err}", "31", use_color)
                if err
                else f"{new} new"
            )

            print(
                f"[retry {i}/{len(failed)}] {sub} -> {status} "
                f"({kept} total)",
                flush=True,
            )

        failed = still_failed

    close_files()

    print(
        f"\ndone, {kept} urls saved to {out_base}",
        flush=True,
    )

    if min_year:
        print(
            f"archive history spans {min_year}-{max_year}",
            flush=True,
        )

    if not args.no_filter:
        print(
            f"{dropped} noise urls dropped",
            flush=True,
        )

    if args.dedupe_paths:
        print(
            f"{collapsed} near-duplicate urls collapsed",
            flush=True,
        )

    if bucket_counts:
        print(
            paint(
                f"\n{hot_count} things worth checking first:",
                "32",
                use_color,
            ),
            flush=True,
        )

        for b in severity:
            if b not in bucket_counts:
                continue

            print(
                f"  {b}: {bucket_counts[b]}",
                flush=True,
            )

            for u, yr in bucket_samples[b]:
                tag = (
                    f" (first seen {yr})"
                    if yr
                    else ""
                )

                print(
                    f"    {u}{tag}",
                    flush=True,
                )

        print(
            f"full list -> {hot_path}",
            flush=True,
        )

    if prev_hot and new_hot:
        new_path = f"{stem}.new.txt"

        with open(new_path, "w") as f:
            f.write("\n".join(new_hot) + "\n")

        print(
            paint(
                f"\n{len(new_hot)} new since your last scan of this -> {new_path}",
                "33",
                use_color,
            ),
            flush=True,
        )

    params_path = None

    if params_seen:
        params_path = f"{stem}.params.txt"

        with open(params_path, "w") as f:
            f.write("\n".join(sorted(params_seen)) + "\n")

        print(
            f"\n{len(params_seen)} unique param names -> {params_path}",
            flush=True,
        )

    paths_path = None

    if seg_seen:
        paths_path = f"{stem}.paths.txt"

        with open(paths_path, "w") as f:
            f.write("\n".join(sorted(seg_seen)) + "\n")

        print(
            f"{len(seg_seen)} unique path segments -> {paths_path}",
            flush=True,
        )

    if failed:
        fail_path = out_base + ".failed"

        with open(fail_path, "w") as f:
            f.write("\n".join(failed) + "\n")

        print(
            f"\n{len(failed)} subdomains still failing, saved to {fail_path}",
            flush=True,
        )

    if args.report:
        report_path = f"{stem}.report.md"

        lines = [
            f"# grabu report — {args.output}",
            "",
            f"{kept} urls across {total} subdomains, sources: {','.join(sources)}",
        ]

        if min_year:
            lines.append(
                f"archive history spans {min_year}-{max_year}"
            )

        lines.append("")
        lines.append(
            f"## worth checking first ({hot_count})"
        )

        for b in severity:
            if b not in bucket_counts:
                continue

            lines.append(
                f"\n### {b} ({bucket_counts[b]})"
            )

            for u, yr in bucket_samples[b]:
                tag = (
                    f" — first seen {yr}"
                    if yr
                    else ""
                )

                lines.append(f"- {u}{tag}")

        lines.append("\n## stats")
        lines.append(f"- {dropped} noise urls dropped")

        if args.dedupe_paths:
            lines.append(
                f"- {collapsed} near-duplicate urls collapsed"
            )

        if params_path:
            lines.append(
                f"- {len(params_seen)} unique param names -> {params_path}"
            )

        if paths_path:
            lines.append(
                f"- {len(seg_seen)} unique path segments -> {paths_path}"
            )

        if prev_hot and new_hot:
            lines.append(
                f"- {len(new_hot)} new interesting hits since the last scan -> {stem}.new.txt"
            )

        if failed:
            lines.append(
                f"- {len(failed)} subdomains still failing -> {out_base}.failed"
            )

        with open(report_path, "w") as f:
            f.write("\n".join(lines) + "\n")

        print(
            f"\nwrote report -> {report_path}",
            flush=True,
        )

    if args.recheck and hot_urls:
        print(
            f"\nrechecking {len(hot_urls)} interesting urls for current liveness...",
            flush=True,
        )

        live = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            for u, code in ex.map(
                lambda u: ping(u, session, 6),
                hot_urls,
            ):
                if code and code < 400:
                    live.append((u, code))

        live_path = f"{stem}.live.txt"

        with open(live_path, "w") as f:
            for u, code in live:
                f.write(f"{u} [{code}]\n")

        print(
            f"{len(live)} of {len(hot_urls)} still respond today -> {live_path}",
            flush=True,
        )


def main():
    args = wizard() if len(sys.argv) == 1 else parse_args()
    run(args)


if __name__ == "__main__":
    main()
