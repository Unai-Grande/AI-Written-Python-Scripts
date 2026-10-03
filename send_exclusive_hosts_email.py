#!/usr/bin/env python3
"""
send_exclusive_hosts_email.py

Gathers the four "exclusive_<source>.csv" files that normalized_key_matrix.py
writes (each source's hosts found nowhere else across the other three), the
two "only in" host+service delta files that lookup_nagios_delta.py writes
(delta_only_in_nagios.csv / delta_only_in_lookup.csv), and that same delta
run's combined workbook (lookup_nagios_delta.xlsx), and emails all seven to
the team as attachments, alongside a short plain-text summary.

The two sets answer different questions and are counted separately in the
body: the exclusive_* files count HOSTS a source has that no other source
does; the delta_only_in_* files count HOST+SERVICE entries one of Nagios /
Lookup File has that the other doesn't (so one host can contribute several
rows). They are not expected to agree.

Before sending, it also checks how OLD the underlying raw source exports
are (nagios_host_services*.csv, application_dashboard_host_services*.csv,
lookup_file*.csv, Splunk_Master_DataSource*.csv - the same files
normalized_key_matrix.py itself reads) and puts that front and center in
the email: if any of them is older than --max-age-hours (default 24) or
simply missing, the subject gets a "[STALE DATA]" prefix and the email
sends ONLY that warning - no CSV attachments and no host-count summary -
since shipping them alongside stale data would look like a normal, current
report when it isn't. Fix the data and re-run to get the real report.
This is a freshness check on the
DATA, separate from the exclusive-files existence check below - a fetch
script (fetch_lookup_file.py / fetch_splunk_master.py) that keeps failing
validation leaves its old file's timestamp untouched, so an aging raw file
is exactly what a silently-repeating fetch failure looks like from here.

Reads only - it runs neither normalized_key_matrix.py nor
lookup_nagios_delta.py itself. Chain them in whatever job runs the
comparison, so both output folders are current before this sends:

  python3 normalized_key_matrix.py && \
  python3 lookup_nagios_delta.py && \
  python3 send_exclusive_hosts_email.py

Input:
  <INPUT_DIR>/exclusive_nagios.csv
  <INPUT_DIR>/exclusive_lookup.csv
  <INPUT_DIR>/exclusive_dashboard.csv
  <INPUT_DIR>/exclusive_splunk.csv
  Default INPUT_DIR = "normalized_key_matrix_output", found next to THIS
  script (not necessarily next to normalized_key_matrix.py) - override with
  --input-dir if that's not where they land.

  <DELTA_DIR>/delta_only_in_nagios*.csv   (newest match is used)
  <DELTA_DIR>/delta_only_in_lookup*.csv   (newest match is used)
  Default DELTA_DIR = "lookup_nagios_delta_output", also found next to THIS
  script - override with --delta-dir. Globbed and picked by mtime the same
  way the raw source exports are, so a timestamped or re-run copy is handled
  without touching this script.

  <DELTA_DIR>/lookup_nagios_delta*.xlsx   (newest match is used)
  The delta run's combined workbook - Summary, Changed, Near Misses and the
  per-server / per-service tabs. Attached as-is, never opened, so openpyxl
  is NOT needed here. Searched in --delta-dir by default (same folder as the
  two delta CSVs); --summary-xlsx-dir searches elsewhere and --summary-xlsx
  names an exact file, which is how you'd send a different workbook instead
  (e.g. normalized_key_matrix_output/normalized_key_matrix.xlsx).

All seven files must exist and be readable or the script exits non-zero
without sending anything - a partial run of the comparison scripts (or one
that hasn't run yet) should never produce a misleadingly incomplete email.
A CSV with 0 data rows is fine and expected (it just means nothing was
exclusive to / only in that source this run) - only a MISSING or unreadable
file is treated as an error. Pass --skip-delta or --skip-summary-xlsx to
send without those pieces.

Usage:
  python3 send_exclusive_hosts_email.py                    # gather + send
  python3 send_exclusive_hosts_email.py --dry-run           # build + print, don't send
  python3 send_exclusive_hosts_email.py --to a@x.org,b@x.org
  python3 send_exclusive_hosts_email.py --input-dir /path/to/normalized_key_matrix_output
  python3 send_exclusive_hosts_email.py --delta-dir /path/to/lookup_nagios_delta_output
  python3 send_exclusive_hosts_email.py --skip-delta        # exclusive_*.csv only
  python3 send_exclusive_hosts_email.py --summary-xlsx /path/to/some_report.xlsx
  python3 send_exclusive_hosts_email.py --skip-summary-xlsx
  python3 send_exclusive_hosts_email.py --raw-source-dir /path/to/raw/exports --max-age-hours 12

Requires: only the standard library (smtplib, email).
"""

import argparse
import csv
import fnmatch
import os
import smtplib
import sys
from datetime import datetime
from email.message import EmailMessage

# ---------------------------------------------------------------------------
# Configuration - edit these for your environment
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INPUT_DIR = os.path.join(SCRIPT_DIR, "normalized_key_matrix_output")

SOURCES = [
    ("nagios", "Nagios"),
    ("lookup", "Lookup File"),
    ("dashboard", "Application Dashboard"),
    ("splunk", "Splunk Master"),
]
FILENAME_TEMPLATE = "exclusive_{source}.csv"

# The host+service "only in" files from lookup_nagios_delta.py. Patterns
# rather than fixed names so the newest match wins (same find_latest_file()
# used for the raw exports below) - the delta script writes fixed names
# today, but a timestamped or archived copy in the same folder shouldn't
# need a code change here.
DEFAULT_DELTA_DIR = os.path.join(SCRIPT_DIR, "lookup_nagios_delta_output")
DELTA_SOURCES = [
    ("nagios", "Nagios", "delta_only_in_nagios*.csv"),
    ("lookup", "Lookup File", "delta_only_in_lookup*.csv"),
]

# The combined workbook lookup_nagios_delta.py writes alongside its delta
# CSVs - the Summary / Changed / Near Misses / per-server / per-service tabs.
# Searched for by pattern in --summary-xlsx-dir, which defaults to
# --delta-dir (the same lookup_nagios_delta_output folder the
# delta_only_in_*.csv files come from), newest match wins. Point
# --summary-xlsx at any other workbook to send that instead, e.g.
# normalized_key_matrix_output/normalized_key_matrix.xlsx.
SUMMARY_XLSX_PATTERN = "lookup_nagios_delta*.xlsx"

# Attachments are read as bytes and typed by extension. An .xlsx sent as
# text/csv (the old hardcoded type) arrives as something Outlook may refuse
# to hand to Excel cleanly, so the workbook needs its real OOXML type.
ATTACHMENT_TYPES = {
    ".csv": ("text", "csv"),
    ".txt": ("text", "plain"),
    ".xlsx": ("application",
              "vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    ".xlsm": ("application", "vnd.ms-excel.sheet.macroEnabled.12"),
    ".zip": ("application", "zip"),
}
DEFAULT_ATTACHMENT_TYPE = ("application", "octet-stream")

# Where the raw exports normalized_key_matrix.py itself reads are expected to
# live, for the freshness check - same patterns as that script's own
# FILE_PATTERNS, so "how old is the data" always means the same thing in
# both places. Default assumes this script is deployed alongside the fetch
# scripts / nagios_full_export.py / scrape_dashboards.py in one folder;
# override with --raw-source-dir if your layout differs.
DEFAULT_RAW_SOURCE_DIR = SCRIPT_DIR
RAW_SOURCE_PATTERNS = [
    ("nagios", "nagios_host_services*.csv"),
    ("dashboard", "application_dashboard_host_services*.csv"),
    ("lookup", "lookup_file*.csv"),
    ("splunk", "Splunk_Master_DataSource*.csv"),
]
DEFAULT_MAX_AGE_HOURS = 24

# Team distribution - replace with your own addresses.
DEFAULT_FROM_ADDR = "noc-reports@example.com"
DEFAULT_TO_ADDRS = ["noc-team@example.com"]
DEFAULT_CC_ADDRS = []

DEFAULT_SUBJECT = "Summary Exclusive Hosts Email"

# Matches cert_monitor.py's existing mail relay - same internal SMTP path
# already used elsewhere in this toolkit, unauthenticated on port 25 unless
# overridden.
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 25
SMTP_USE_TLS = False
SMTP_USERNAME = None
SMTP_PASSWORD = None  # only used if SMTP_USERNAME is set

ENCODING_ATTEMPTS = ["utf-8-sig", "cp1252", "latin-1"]


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")


def count_rows(path):
    """Return the number of data rows in a CSV (header not counted). Tries
    each encoding in ENCODING_ATTEMPTS. Raises if the file can't be parsed
    at all - a row count of 0 (a valid, expected outcome: nothing exclusive
    this run) is different from "couldn't read this file"."""
    last_err = None
    for enc in ENCODING_ATTEMPTS:
        try:
            with open(path, encoding=enc, newline="") as f:
                # minus header; max() guards a completely empty file, which
                # would otherwise report -1 rows
                return max(0, sum(1 for _ in csv.reader(f)) - 1)
        except UnicodeDecodeError as e:
            last_err = e
            continue
    raise last_err


def find_latest_file(directory, pattern):
    """Newest file in directory matching pattern (case-insensitive), or
    None if the directory doesn't exist or nothing matches."""
    try:
        entries = os.listdir(directory)
    except OSError:
        return None
    matches = [os.path.join(directory, e) for e in entries
               if fnmatch.fnmatch(e.lower(), pattern.lower())]
    if not matches:
        return None
    return max(matches, key=os.path.getmtime)


def check_freshness(raw_source_dir, max_age_hours):
    """
    Checks how old each raw source export is. Returns [(label, status,
    detail), ...] in SOURCES order, where status is "OK", "STALE", or
    "MISSING". A file is only as fresh as its last SUCCESSFUL update - if
    fetch_lookup_file.py / fetch_splunk_master.py have been failing
    validation and leaving the old file in place, its age just keeps
    climbing, so this catches that automatically without needing to know
    anything about why the fetch failed.
    """
    now = datetime.now().timestamp()
    results = []
    for source, pattern in RAW_SOURCE_PATTERNS:
        label = dict(SOURCES)[source]
        path = find_latest_file(raw_source_dir, pattern)
        if path is None:
            results.append((label, "MISSING", f"no file matching '{pattern}' found in {raw_source_dir}"))
            continue
        age_hours = (now - os.path.getmtime(path)) / 3600
        mtime_str = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M")
        detail = f"{os.path.basename(path)} - last updated {mtime_str} ({age_hours:.1f}h ago)"
        if age_hours > max_age_hours:
            results.append((label, "STALE", f"{detail}, older than the {max_age_hours}h threshold"))
        else:
            results.append((label, "OK", detail))
    return results


def build_freshness_section(freshness_results):
    """Plain-text block summarizing check_freshness()'s results, meant to
    sit at the very top of the email body so a stale or missing source is
    the first thing anyone sees, not something buried in the counts below."""
    any_bad = any(status != "OK" for _, status, _ in freshness_results)
    lines = []
    if any_bad:
        lines.append("*** WARNING: NOT ALL SOURCE DATA IS CURRENT - see below ***")
    else:
        lines.append("Data freshness: OK - all four raw sources are current.")
    lines.append("")
    for label, status, detail in freshness_results:
        marker = {"OK": "OK", "STALE": "STALE", "MISSING": "MISSING"}[status]
        lines.append(f"  [{marker:7s}] {label}: {detail}")
    lines.append("")
    return any_bad, "\n".join(lines)


def gather_files(input_dir):
    """
    Verify all four exclusive_<source>.csv files exist and are readable,
    returning [(label, path, row_count), ...] in SOURCES order. Exits
    non-zero with a clear message (nothing sent) if any are missing or
    unreadable, rather than emailing a partial/misleading report.
    """
    gathered = []
    missing = []
    for source, label in SOURCES:
        path = os.path.join(input_dir, FILENAME_TEMPLATE.format(source=source))
        if not os.path.isfile(path):
            missing.append(path)
            continue
        try:
            rows = count_rows(path)
        except Exception as e:
            missing.append(f"{path} (unreadable: {e})")
            continue
        gathered.append((label, path, rows))

    if missing:
        log(f"[FATAL] Missing or unreadable file(s) in {input_dir!r}:")
        for m in missing:
            log(f"    {m}")
        log("Has normalized_key_matrix.py been run against this directory yet? "
            "Nothing was sent.")
        sys.exit(1)
    return gathered


def gather_delta_files(delta_dir):
    """
    Locate the newest delta_only_in_nagios*.csv / delta_only_in_lookup*.csv
    in delta_dir, returning [(label, path, row_count), ...] in DELTA_SOURCES
    order. Same contract as gather_files(): exits non-zero with a clear
    message (nothing sent) if either is missing or unreadable, since an
    email that quietly drops one side of the delta is worse than no email.
    0 data rows is valid and reported as 0.
    """
    gathered = []
    missing = []
    for _source, label, pattern in DELTA_SOURCES:
        path = find_latest_file(delta_dir, pattern)
        if path is None:
            missing.append(f"no file matching '{pattern}' in {delta_dir}")
            continue
        try:
            rows = count_rows(path)
        except Exception as e:
            missing.append(f"{path} (unreadable: {e})")
            continue
        gathered.append((label, path, rows))

    if missing:
        log("[FATAL] Missing or unreadable delta file(s):")
        for m in missing:
            log(f"    {m}")
        log("Has lookup_nagios_delta.py been run against this directory yet? "
            "Use --delta-dir to point elsewhere, or --skip-delta to send "
            "without them. Nothing was sent.")
        sys.exit(1)
    return gathered


def gather_summary_xlsx(explicit_path, search_dir):
    """
    Locate the summary workbook to attach. An explicit --summary-xlsx path
    wins outright; otherwise the newest SUMMARY_XLSX_PATTERN match in
    search_dir is used. Returns its path, or exits non-zero (nothing sent)
    if it's missing or unreadable - same contract as the CSV gatherers, so
    the email is never quietly missing a piece.
    """
    if explicit_path:
        path = explicit_path
        if not os.path.isfile(path):
            log(f"[FATAL] --summary-xlsx {path!r} is not a file. Nothing was sent.")
            sys.exit(1)
    else:
        path = find_latest_file(search_dir, SUMMARY_XLSX_PATTERN)
        if path is None:
            log(f"[FATAL] No file matching '{SUMMARY_XLSX_PATTERN}' in {search_dir}.")
            log("Has lookup_nagios_delta.py been run against this directory yet? "
                "Use --summary-xlsx to point at the workbook directly, "
                "--summary-xlsx-dir to search elsewhere, or --skip-summary-xlsx "
                "to send without it. Nothing was sent.")
            sys.exit(1)

    try:
        with open(path, "rb") as f:
            f.read(1)
    except OSError as e:
        log(f"[FATAL] Can't read {path} ({e}). Nothing was sent.")
        sys.exit(1)
    return path


def build_summary_text(gathered, delta_gathered, input_dir, freshness_section):
    """
    gathered: [(label, path, row_count), ...] in SOURCES order
    (nagios, lookup, dashboard, splunk). The email body maps these onto the
    requested fixed labels/order below (Nagios, Application, Splunk,
    LookUp), independent of the internal source order/naming.

    delta_gathered: [(label, path, row_count), ...] in DELTA_SOURCES order
    (nagios, lookup), or [] when --skip-delta was passed - in which case the
    host+service section is omitted entirely rather than printed as zeros.
    Those counts are host+service ENTRIES, not hosts, so they get their own
    labelled block instead of being mixed in with the host counts above.
    """
    counts_by_source = {}
    for (source, _label), (_disp_label, _path, rows) in zip(SOURCES, gathered):
        counts_by_source[source] = rows

    body_fields = [
        ("nagios", "Hosts in Nagios"),
        ("dashboard", "Hosts in Application"),
        ("splunk", "Hosts in Splunk"),
        ("lookup", "Hosts in LookUp"),
    ]
    lines = [freshness_section, DEFAULT_SUBJECT, ""]
    for source, field_label in body_fields:
        lines.append(f"{field_label}: {counts_by_source[source]}")

    if delta_gathered:
        delta_counts = {}
        for (source, _label, _pattern), (_disp, _path, rows) in zip(
                DELTA_SOURCES, delta_gathered):
            delta_counts[source] = rows
        delta_fields = [
            ("nagios", "Host and Services in Nagios"),
            ("lookup", "Host and Services in LookUp"),
        ]
        lines.append("")
        for source, field_label in delta_fields:
            lines.append(f"{field_label}: {delta_counts[source]}")

    lines += ["", f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}"]
    return "\n".join(lines)


def send_email(subject, body_text, attachments, from_addr, to_addrs, cc_addrs):
    """attachments: [(display_filename, path), ...]"""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)
    msg.set_content(body_text)

    for display_name, path in attachments:
        maintype, subtype = ATTACHMENT_TYPES.get(
            os.path.splitext(path)[1].lower(), DEFAULT_ATTACHMENT_TYPE)
        with open(path, "rb") as f:
            msg.add_attachment(
                f.read(), maintype=maintype, subtype=subtype, filename=display_name
            )

    all_recipients = to_addrs + cc_addrs
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30) as server:
        if SMTP_USE_TLS:
            server.starttls()
        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg, from_addr=from_addr, to_addrs=all_recipients)


def main():
    ap = argparse.ArgumentParser(
        description="Email normalized_key_matrix.py's four exclusive-hosts CSVs plus "
                    "lookup_nagios_delta.py's two 'only in' CSVs and its workbook."
    )
    ap.add_argument("--input-dir", default=DEFAULT_INPUT_DIR,
                    help=f"Directory containing exclusive_*.csv (default: {DEFAULT_INPUT_DIR})")
    ap.add_argument("--delta-dir", default=DEFAULT_DELTA_DIR,
                    help=f"Directory containing delta_only_in_*.csv (default: {DEFAULT_DELTA_DIR})")
    ap.add_argument("--skip-delta", action="store_true",
                    help="Don't attach or count the lookup_nagios_delta.py 'only in' files")
    ap.add_argument("--summary-xlsx", default=None,
                    help="Exact path of the summary workbook to attach "
                         f"(default: newest '{SUMMARY_XLSX_PATTERN}' in --summary-xlsx-dir)")
    ap.add_argument("--summary-xlsx-dir", default=None,
                    help="Directory to search for the summary workbook (default: --delta-dir)")
    ap.add_argument("--skip-summary-xlsx", action="store_true",
                    help="Don't attach the summary workbook")
    ap.add_argument("--from", dest="from_addr", default=DEFAULT_FROM_ADDR,
                    help=f"From address (default: {DEFAULT_FROM_ADDR})")
    ap.add_argument("--to", default=",".join(DEFAULT_TO_ADDRS),
                    help=f"Comma-separated recipient list (default: {','.join(DEFAULT_TO_ADDRS)})")
    ap.add_argument("--cc", default=",".join(DEFAULT_CC_ADDRS),
                    help="Comma-separated Cc list (default: none)")
    ap.add_argument("--subject", default=None,
                    help="Override the default subject line")
    ap.add_argument("--raw-source-dir", default=DEFAULT_RAW_SOURCE_DIR,
                    help=f"Directory to check the raw source exports' ages in (default: {DEFAULT_RAW_SOURCE_DIR})")
    ap.add_argument("--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS,
                    help=f"Flag a raw source as stale past this many hours old (default: {DEFAULT_MAX_AGE_HOURS})")
    ap.add_argument("--skip-freshness-check", action="store_true",
                    help="Skip the raw-data freshness check entirely (not recommended)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Build the email and print it instead of sending")
    args = ap.parse_args()

    to_addrs = [a.strip() for a in args.to.split(",") if a.strip()]
    cc_addrs = [a.strip() for a in args.cc.split(",") if a.strip()]
    if not to_addrs:
        sys.exit("ERROR: no recipients - pass --to or set DEFAULT_TO_ADDRS.")

    log(f"Gathering exclusive-host files from {args.input_dir!r} ...")
    gathered = gather_files(args.input_dir)
    for label, path, rows in gathered:
        log(f"  {label:<22} {rows:4d} exclusive host(s) -> {path}")

    if args.skip_delta:
        delta_gathered = []
        log("--skip-delta set: not gathering the 'only in' host+service files.")
    else:
        log(f"Gathering host+service delta files from {args.delta_dir!r} ...")
        delta_gathered = gather_delta_files(args.delta_dir)
        for label, path, rows in delta_gathered:
            log(f"  {label:<22} {rows:4d} host+service entry(ies) only here -> {path}")

    if args.skip_summary_xlsx:
        summary_xlsx = None
        log("--skip-summary-xlsx set: not attaching the summary workbook.")
    else:
        xlsx_dir = args.summary_xlsx_dir or args.delta_dir
        log(f"Locating summary workbook ({'explicit path' if args.summary_xlsx else xlsx_dir!r}) ...")
        summary_xlsx = gather_summary_xlsx(args.summary_xlsx, xlsx_dir)
        size_kb = os.path.getsize(summary_xlsx) / 1024
        log(f"  {'Summary workbook':<22} {size_kb:7.1f} KB -> {summary_xlsx}")

    if args.skip_freshness_check:
        any_bad, freshness_section = False, ""
    else:
        log(f"Checking raw source data age in {args.raw_source_dir!r} "
            f"(threshold: {args.max_age_hours}h) ...")
        freshness_results = check_freshness(args.raw_source_dir, args.max_age_hours)
        any_bad, freshness_section = build_freshness_section(freshness_results)
        for label, status, detail in freshness_results:
            log(f"  [{status:7s}] {label}: {detail}")
        if any_bad:
            log("[WARNING] Not all source data is current - flagging this in the email.")

    subject = args.subject or DEFAULT_SUBJECT
    if any_bad:
        subject = f"[STALE DATA] {subject}"
        log("[WARNING] Withholding attachments and host-count summary - "
            "sending a freshness alert only.")
        body = (
            freshness_section
            + "Attachments and all counts are withheld while source data is stale or "
              "missing - sending them as usual could look like a normal, current report "
              "when it isn't. Re-run once the data above is fixed.\n"
        )
        attachments = []
    else:
        body = build_summary_text(gathered, delta_gathered, args.input_dir,
                                  freshness_section)
        attachments = [(os.path.basename(path), path)
                       for _, path, _ in gathered + delta_gathered]
        if summary_xlsx:
            attachments.append((os.path.basename(summary_xlsx), summary_xlsx))

    if args.dry_run:
        log("--dry-run set: not sending. Preview below.\n")
        print(f"From: {args.from_addr}")
        print(f"To: {', '.join(to_addrs)}")
        if cc_addrs:
            print(f"Cc: {', '.join(cc_addrs)}")
        print(f"Subject: {subject}")
        print(f"Attachments: {[name for name, _ in attachments]}")
        print()
        print(body)
        return

    log(f"Sending via {SMTP_SERVER}:{SMTP_PORT} to {to_addrs} (cc {cc_addrs or 'none'}) ...")
    try:
        send_email(subject, body, attachments, args.from_addr, to_addrs, cc_addrs)
    except Exception as e:
        log(f"[FATAL] Could not send email: {e}")
        sys.exit(1)
    log("Email sent.")


if __name__ == "__main__":
    main()