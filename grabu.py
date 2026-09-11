import argparse
import concurrent.futures
import json
import posixpath
import signal
import sys
import threading
import time
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


ARCHIVE_SOURCES = ["wayback", "commoncrawl"]


noise_ext = {
    "jpg", "jpeg", "png", "gif", "svg", "ico", "webp",
    "bmp", "tiff", "tif", "avif",
    "woff", "woff2", "ttf", "eot", "otf",
    "css",
    "mp4", "mp3", "avi", "mov", "wav", "webm",
    "ogg", "flv", "m4a", "m4v", "mkv", "swf",
}


interesting_ext = {
    "env", "git", "sql", "db", "sqlite", "sqlite3",
    "bak", "backup", "old", "orig",
    "zip", "tar", "gz", "tgz", "rar", "7z",
    "pem", "key", "pfx", "p12", "crt",
    "log", "yml", "yaml", "conf", "config",
    "ini", "properties",
    "json", "xml", "csv", "doc", "docx",
    "xls", "xlsx", "pdf", "dump", "sh", "ps1",
}


interesting_kw = [
    "wp-config", "htaccess", "htpasswd", "phpinfo",
    "web.config", "docker-compose",
    ".aws", "id_rsa", ".npmrc", ".pypirc", ".ssh",
    "credential", "password", "secret",
    "token", "apikey", "api_key",
    "backup", "dump", "swagger", "api-docs", "actuator",
    ".well-known", "/private/", "/internal/",
    ".git/", ".svn/", ".ds_store",
    "config.php", "settings.py",
]


def url_ext(url):
    path = urlparse(url).path
    return posixpath.splitext(path)[1].lstrip(".").lower()


def noise(url):
    return url_ext(url) in noise_ext


def interesting(url):
    if url_ext(url) in interesting_ext:
        return True

    low = url.lower()
    return any(keyword in low for keyword in interesting_kw)


class RateLimiter:

    def __init__(self, rps):
        self.interval = 1.0 / rps if rps > 0 else 0
        self.lock = threading.Lock()
        self.next_time = 0.0

    def wait(self):
        if self.interval <= 0:
            return

        with self.lock:
            now = time.monotonic()
            sleep_for = max(0.0, self.next_time - now)
            self.next_time = max(now, self.next_time) + self.interval

        if sleep_for > 0:
            time.sleep(sleep_for)


def build_session():

    session = requests.Session()

    retry = Retry(
        total=5,
        backoff_factor=3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        respect_retry_after_header=True,
    )

    adapter = HTTPAdapter(max_retries=retry)

    session.mount("https://", adapter)
    session.mount("http://", adapter)

    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; grabu/1.0)"
    })

    return session


def fetch_wayback(subdomain, session, timeout):

    params = {
        "url": f"{subdomain}/*",
        "output": "text",
        "fl": "original",
        "collapse": "urlkey",
    }

    response = session.get(
        "https://web.archive.org/cdx/search/cdx",
        params=params,
        timeout=timeout,
    )

    response.raise_for_status()

    return [
        line
        for line in response.text.splitlines()
        if line.strip()
    ]


def get_commoncrawl_index(session, timeout):

    response = session.get(
        "https://index.commoncrawl.org/collinfo.json",
        timeout=timeout,
    )

    response.raise_for_status()

    data = response.json()

    return data[0]["cdx-api"]


def fetch_commoncrawl(subdomain, session, timeout, cc_index):

    params = {
        "url": f"{subdomain}/*",
        "output": "json",
    }

    response = session.get(
        cc_index,
        params=params,
        timeout=timeout,
    )

    if response.status_code == 404:
        return []

    response.raise_for_status()

    urls = []

    for line in response.text.splitlines():

        line = line.strip()

        if not line:
            continue

        try:
            record = json.loads(line)
            url = record.get("url")

        except json.JSONDecodeError:
            continue

        if url:
            urls.append(url)

    return urls


def fetch(
    subdomain,
    session,
    timeout,
    limiters,
    semaphores,
    selected_sources,
    cc_index,
    verbose=False,
):

    urls = []
    errors = []

    for source in selected_sources:

        limiters[source].wait()

        semaphore = semaphores[source]
        semaphore.acquire()

        if verbose:
            print(
                f"    -> {source} requesting {subdomain}",
                flush=True,
            )

        start = time.monotonic()

        try:

            if source == "wayback":

                found = fetch_wayback(
                    subdomain,
                    session,
                    timeout,
                )

            elif source == "commoncrawl":

                found = fetch_commoncrawl(
                    subdomain,
                    session,
                    timeout,
                    cc_index,
                )

            else:
                found = []

            urls.extend(found)

            if verbose:
                elapsed = time.monotonic() - start

                print(
                    f"    <- {source} {subdomain}: "
                    f"{len(found)} urls in {elapsed:.1f}s",
                    flush=True,
                )

        except Exception as error:

            if verbose:
                elapsed = time.monotonic() - start

                print(
                    f"    <- {source} {subdomain}: "
                    f"failed after {elapsed:.1f}s ({error})",
                    flush=True,
                )

            errors.append(f"{source}: {error}")

        finally:
            semaphore.release()

    error_text = "; ".join(errors) if errors else None

    return subdomain, urls, error_text


def prompt(message, default=""):

    if default:
        value = input(
            f"{message} [{default}]: "
        ).strip()

    else:
        value = input(
            f"{message}: "
        ).strip()

    return value or default


def interactive_args():

    print(
        "grabu - interactive setup "
        "(enter to accept defaults)\n"
    )

    file = prompt("subdomains file")

    while not file:
        file = prompt("subdomains file")

    output = prompt("output file", "combined.txt")

    print(
        "\nsources: "
        "1) wayback "
        "2) commoncrawl (backup, patchier coverage) "
        "3) both"
    )

    choice = prompt("pick a source", "1")

    source_map = {
        "1": "wayback",
        "2": "commoncrawl",
        "3": "all",
    }

    source = source_map.get(choice, "wayback")

    threads = int(prompt("threads", "20"))

    rps = float(
        prompt("requests/sec per source", "2.0")
    )

    concurrency = int(
        prompt(
            "max simultaneous in-flight requests per source",
            "5",
        )
    )

    timeout = int(
        prompt("per-request timeout (sec)", "20")
    )

    filter_answer = prompt(
        "filter out noise urls (images/css/fonts/etc)? y/n",
        "y",
    )

    verbose_answer = prompt(
        "verbose per-request logging? y/n",
        "n",
    )

    print()

    return argparse.Namespace(
        file=file,
        output=output,
        threads=threads,
        timeout=timeout,
        rps=rps,
        concurrency=concurrency,
        no_filter=filter_answer.lower().startswith("n"),
        source=source,
        verbose=verbose_answer.lower().startswith("y"),
    )


def parse_args():

    parser = argparse.ArgumentParser(
        description=(
            "grab all indexed urls for a list of "
            "subdomains from Wayback Machine and Common Crawl"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "example: python3 grabu.py "
            "-f subs.txt -o combined.txt "
            "-t 20 --rps 2 -s wayback\n"
            "tip: run with no arguments at all "
            "(just `python3 grabu.py`) to get "
            "interactive input prompts instead of flags"
        ),
    )

    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="txt file with one subdomain per line",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="combined.txt",
        help="where deduped urls get written",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=20,
        help="worker threads",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="per-request timeout in seconds",
    )

    parser.add_argument(
        "--rps",
        type=float,
        default=2.0,
        help="max requests/sec per source",
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="max simultaneous requests per source",
    )

    parser.add_argument(
        "-s",
        "--source",
        choices=ARCHIVE_SOURCES + ["all"],
        default="wayback",
        help="archive source to use",
    )

    parser.add_argument(
        "--no-filter",
        action="store_true",
        help="disable noise filtering",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print every request",
    )

    return parser.parse_args()


def run(args):

    # Important: don't assign to the global ARCHIVE_SOURCES.
    selected_sources = (
        ARCHIVE_SOURCES
        if args.source == "all"
        else [args.source]
    )

    try:

        with open(args.file, encoding="utf-8") as file:

            subdomains = sorted(
                set(
                    line.strip()
                    for line in file
                    if line.strip()
                    and not line.startswith("#")
                )
            )

    except FileNotFoundError:

        print(f"no such file: {args.file}")
        sys.exit(1)

    if not subdomains:

        print("no subdomains found in file")
        sys.exit(1)

    session = build_session()

    cc_index = None

    if "commoncrawl" in selected_sources:

        try:

            cc_index = get_commoncrawl_index(
                session,
                args.timeout,
            )

        except Exception as error:

            print(
                "couldn't reach commoncrawl index, "
                f"dropping it from this run: {error}",
                flush=True,
            )

            selected_sources = [
                source
                for source in selected_sources
                if source != "commoncrawl"
            ]

    if not selected_sources:

        print("no usable sources left", flush=True)
        sys.exit(1)

    print(
        f"{len(subdomains)} subdomains, "
        f"sources: {','.join(selected_sources)}, "
        f"{args.threads} threads, "
        f"{args.rps} req/s/source cap, "
        f"writing to {args.output}",
        flush=True,
    )

    seen = set()
    dropped = 0
    interesting_count = 0

    lock = threading.Lock()

    out = open(args.output, "w", buffering=1, encoding="utf-8")

    stem, ext = posixpath.splitext(args.output)

    interesting_path = (
        f"{stem}.interesting{ext or '.txt'}"
    )

    interesting_out = open(
        interesting_path,
        "w",
        buffering=1,
        encoding="utf-8",
    )

    limiters = {
        source: RateLimiter(args.rps)
        for source in selected_sources
    }

    caps = {
        source: (
            min(args.concurrency, 2)
            if source == "commoncrawl"
            else args.concurrency
        )
        for source in selected_sources
    }

    semaphores = {
        source: threading.Semaphore(caps[source])
        for source in selected_sources
    }

    done = 0
    failed = []
    total = len(subdomains)

    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=args.threads
    )

    futures = {
        executor.submit(
            fetch,
            subdomain,
            session,
            args.timeout,
            limiters,
            semaphores,
            selected_sources,
            cc_index,
            args.verbose,
        ): subdomain
        for subdomain in subdomains
    }

    def flush_and_exit():

        print(
            f"\nstopped, {len(seen)} urls saved to "
            f"{args.output} "
            f"({done}/{total} subdomains processed)",
            flush=True,
        )

        out.flush()
        out.close()

        interesting_out.flush()
        interesting_out.close()

        executor.shutdown(
            wait=False,
            cancel_futures=True,
        )

        sys.exit(0)

    signal.signal(
        signal.SIGINT,
        lambda sig, frame: flush_and_exit(),
    )

    def record(urls):

        nonlocal dropped, interesting_count

        new = 0

        with lock:

            for url in urls:

                if url in seen:
                    continue

                if not args.no_filter and noise(url):

                    dropped += 1
                    continue

                seen.add(url)

                out.write(url + "\n")

                new += 1

                if interesting(url):

                    interesting_out.write(url + "\n")
                    interesting_count += 1

        return new

    for future in concurrent.futures.as_completed(futures):

        subdomain = futures[future]

        _, urls, error = future.result()

        new = record(urls)

        done += 1

        if error:
            failed.append(subdomain)

        status = (
            f"err: {error}"
            if error
            else f"{new} new"
        )

        print(
            f"[{done}/{total}] "
            f"{subdomain} -> {status} "
            f"({len(seen)} total)",
            flush=True,
        )

    if failed:

        print(
            f"\n{len(failed)} subdomains failed, "
            "retrying sequentially at a slower pace...",
            flush=True,
        )

        slow_limiters = {
            source: RateLimiter(
                max(0.5, args.rps / 4)
            )
            for source in selected_sources
        }

        slow_semaphores = {
            source: threading.Semaphore(1)
            for source in selected_sources
        }

        still_failed = []

        for index, subdomain in enumerate(failed, 1):

            _, urls, error = fetch(
                subdomain,
                session,
                args.timeout,
                slow_limiters,
                slow_semaphores,
                selected_sources,
                cc_index,
                args.verbose,
            )

            new = record(urls)

            if error:
                still_failed.append(subdomain)

            status = (
                f"err: {error}"
                if error
                else f"{new} new"
            )

            print(
                f"[retry {index}/{len(failed)}] "
                f"{subdomain} -> {status} "
                f"({len(seen)} total)",
                flush=True,
            )

        failed = still_failed

    out.close()
    interesting_out.close()

    print(
        f"\ndone, {len(seen)} urls saved to {args.output}",
        flush=True,
    )

    if not args.no_filter:

        print(
            f"{dropped} noise urls dropped",
            flush=True,
        )

    print(
        f"{interesting_count} flagged as interesting "
        f"-> {interesting_path}",
        flush=True,
    )

    if failed:

        fail_path = args.output + ".failed"

        with open(fail_path, "w", encoding="utf-8") as file:

            file.write("\n".join(failed) + "\n")

        print(
            f"{len(failed)} subdomains still failing, "
            f"saved to {fail_path}",
            flush=True,
        )


def main():

    if len(sys.argv) == 1:
        args = interactive_args()
    else:
        args = parse_args()

    run(args)


if __name__ == "__main__":
    main()
