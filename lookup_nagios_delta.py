#!/usr/bin/env python3
"""
lookup_nagios_delta.py

The DELTA between the Lookup File and the Nagios export: what one has that
the other doesn't, and - the part the comparison scripts don't answer -
where both have the same entry but disagree about its details.

The three sibling comparison scripts (primary_key_comparison.py,
full_hostname_key_comparison.py, ip_service_key_comparison.py) all answer
one question: "is this key present in the other source, yes or no". This
script answers a different one: "what actually changed between them",
which includes entries present on both sides whose IP address, governing
Nagios server, dashboard or host spelling disagree. Those entries are
invisible to a presence check - they read as a clean match - but they are
usually the ones worth fixing, because both systems think they are right.

Every entry lands in exactly one of four buckets:

  ONLY IN NAGIOS   monitored, but the Lookup File has no such entry -
                   nothing to route alerts by
  ONLY IN LOOKUP   listed for alerting, but Nagios isn't monitoring it -
                   the alert can never fire
  CHANGED          present in both, but at least one comparable field
                   disagrees - listed field by field, with both values
  IDENTICAL        present in both and every comparable field agrees

Comparable fields are the ones both exports actually carry: Host (the raw
spelling each source used), IP Address, Nagios Server and Dashboard.
Fields only one side has - Nagios's ping/SNMP/duration/command, the Lookup
File's application name and distribution list - are carried through as
context on the ONLY IN rows, but are never reported as a "difference",
since one side having a column the other lacks is not a disagreement.

KEYING
  Entries are aligned on host + service, and --key-mode picks which host
  form to align on, matching the three sibling scripts:
    short (default)  host name cut to the part before the first '.', with
                     role-suffixed names folded onto their clean hostname
                     (primary_key_comparison.py's behaviour)
    full             host name exactly as recorded - suffixes and domains
                     kept distinct (full_hostname_key_comparison.py)
    ip               IP address instead of the host name; rows with no
                     usable address cannot be keyed and are counted as
                     skipped (ip_service_key_comparison.py)
  Service values are reconciled through SERVICE_ALIASES first either way,
  so ping-only hosts ("N/A" in Nagios, "PINGONLY" in the Lookup File) and
  the known typo/convention variants line up rather than showing as a
  spurious add plus a spurious removal.

DELIBERATE CHOICE ABOUT SERVERS
  There is no --server-scoped mode here. The sibling scripts refuse to
  match two rows tagged to different physical Nagios servers, which is
  right when the question is "is it present". For a delta it is the wrong
  shape: a host both sources know about but disagree about the server for
  is not an add and a removal, it is one entry with a changed field, and
  that is how it is reported - as a CHANGED row on "Nagios Server", with
  both values side by side.

Same conventions as the rest of the toolkit: file patterns are matched
case-insensitively with the newest match winning, encodings are tried in
order, and if either source file is older than --max-age-hours (default 24)
the Summary tab opens with a large bold red STALE DATA banner.

Output (in OUTPUT_DIR - a new directory created next to THIS script):
  - delta_all.csv              every entry with its bucket
  - delta_only_in_nagios.csv   monitored but not routed
  - delta_only_in_lookup.csv   routed but not monitored
  - delta_changed.csv          one row per disagreeing field, both values
  - lookup_nagios_delta.xlsx   the above as tabs, plus a Summary tab
                               explaining the method and counting each
                               bucket

Usage:
  python3 lookup_nagios_delta.py
  python3 lookup_nagios_delta.py --key-mode full
  python3 lookup_nagios_delta.py --key-mode ip
  python3 lookup_nagios_delta.py --ignore-field Dashboard --ignore-field Host
  python3 lookup_nagios_delta.py --input-dir /path/to/exports --output-dir /path/out

Requires: openpyxl for the XLSX output only; the CSVs use the standard
library alone. Tested against Python 3.9.
"""

import argparse
import csv
import difflib
import fnmatch
import os
import re
import sys
from collections import OrderedDict
from datetime import datetime

# ----------------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INPUT_DIR = SCRIPT_DIR
DEFAULT_OUTPUT_DIR = os.path.join(SCRIPT_DIR, "lookup_nagios_delta_output")

FILE_PATTERNS = {
    "nagios": "nagios_host_services*.csv",
    "lookup": "lookup_file*.csv",
}
SOURCE_LABELS = {"nagios": "Nagios", "lookup": "Lookup File"}

# host field, IP field, server-reference field, service field, per source
SOURCE_FIELDS = {
    "nagios": {"host": "Host", "ip": "IP Address", "server_ref": "Dashboard", "service": "Service"},
    "lookup": {"host": "Host", "ip": "IP_Address", "server_ref": "Dashboard", "service": "Service"},
}

# Fields both exports carry, so a disagreement is a real disagreement rather
# than one side simply not having the column. (output label, nagios column,
# lookup column)
COMPARE_FIELDS = [
    ("Host", "Host", "Host"),
    ("IP Address", "IP Address", "IP_Address"),
    ("Nagios Server", "Nagios Server", "Nagios Server"),
    ("Dashboard", "Dashboard", "Dashboard"),
]

# Carried through as context on ONLY IN rows - never compared, because the
# other source has no equivalent column to disagree with.
CONTEXT_FIELDS = {
    "nagios": [("Pingable", "Pingable"), ("SNMP Connectivity", "SNMP Connectivity"),
               ("Duration", "Duration"), ("Status Information", "Status Information"),
               ("Command", "Command")],
    "lookup": [("Application Name", "Application_Name"),
               ("Distribution List", "Distribution_List")],
}

DEFAULT_MAX_AGE_HOURS = 24

SERVER_HOST_TO_NAGIOS_IP = {
    "NAME1.EXAMPLE.COM": "192.0.2.10",
    "NAME2.EXAMPLE.COM": "192.0.2.11",
    "NAME3.EXAMPLE.COM": "192.0.2.12",
}
SERVER_HOST_RE = re.compile(r"(name[1-3]\.example\.com)", re.IGNORECASE)
DIRECT_IP_URL_RE = re.compile(r"https?://(\d{1,3}(?:\.\d{1,3}){3})")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
EXPLICIT_SERVER_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/[A-Za-z0-9_.-]+)?$")

ENCODING_ATTEMPTS = ["utf-8-sig", "cp1252", "latin-1"]

# Values that mean "we don't have one" rather than being a real value. Used
# both when keying on IP and when deciding whether two values disagree - a
# blank on one side and "N/A" on the other is not a disagreement worth
# reporting.
PLACEHOLDERS = {"", "N/A", "NA", "NONE", "NULL", "-", "TBD", "UNKNOWN", "0.0.0.0"}

# Service-name reconciliation, same table as the comparison scripts. Applied
# before keying so the two sources' different words for the same check line
# up instead of producing a paired add + removal.
PING_ONLY_CANONICAL = "PING-ONLY"
SERVICE_ALIASES = {
    "N/A": PING_ONLY_CANONICAL,
    "PINGONLY": PING_ONLY_CANONICAL,
    "PING ONLY": PING_ONLY_CANONICAL,
    "PING-ONLY": PING_ONLY_CANONICAL,
    "CPU_USAG": "CPU_USAGE",
    "CPU": "CPU_USAGE",
    "MEMORY": "MEMORY_USAGE",
    "DISK_C": "C DRIVE",
    "DISK_D": "D DRIVE",
}

# Host names that mean "the monitoring server itself" rather than naming a
# machine. Nagios runs a lot of checks FROM the monitoring box - certificate
# checks, HTTP probes against remote URLs - and files them under localhost,
# while the Lookup File attributes the same check to the real target host.
# Neither is wrong; they just disagree about what the "host" of a remote
# probe is, and a plain host+service key can never reconcile that.
LOCALHOST_NAMES = {"LOCALHOST", "LOCALHOST.LOCALDOMAIN", "127.0.0.1", "::1"}

# A localhost entry is only rescued when its service points at few enough
# counterparts to be unambiguous. Service names like
# "SRV01WEB009_HTTPS_PORTAL_..." embed their target and resolve to
# exactly one host, so matching on the service alone is safe. Generic names
# like UPTIME or PING do not: the monitoring server's own uptime check is a
# real, distinct thing, and pairing it with some unrelated host's UPTIME
# would invent a match rather than find one.
DEFAULT_LOCALHOST_MAX_CANDIDATES = 1

BUCKET_ONLY_NAGIOS = "ONLY IN NAGIOS"
BUCKET_ONLY_LOOKUP = "ONLY IN LOOKUP"
BUCKET_CHANGED = "CHANGED"
BUCKET_IDENTICAL = "IDENTICAL"
BUCKET_LOCALHOST = "MATCHED VIA LOCALHOST"


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def find_latest_file(input_dir, pattern, label):
    try:
        entries = os.listdir(input_dir)
    except OSError as e:
        sys.exit(f"ERROR: cannot list '{input_dir}': {e}")
    matches = [os.path.join(input_dir, e) for e in entries
               if fnmatch.fnmatch(e.lower(), pattern.lower())]
    if not matches:
        sys.exit(f"ERROR: no file matching '{pattern}' found in '{input_dir}' "
                 f"for the {label} source. Check FILE_PATTERNS / --input-dir.")
    return max(matches, key=os.path.getmtime)


def read_csv_robust(path):
    last_err = None
    for enc in ENCODING_ATTEMPTS:
        try:
            with open(path, encoding=enc, newline="") as f:
                return list(csv.DictReader(f))
        except UnicodeDecodeError as e:
            last_err = e
            continue
    raise last_err


def is_placeholder(value):
    return (value or "").strip().upper() in PLACEHOLDERS


def servers_differ(a, b):
    """
    Nagios Server needs its own comparison. The Nagios export tags a
    per-instance server's dashboards as "192.0.2.11/amicus" while the Lookup
    File records the bare "192.0.2.11" - that is the SAME physical server
    described at two levels of detail, not a disagreement, and reporting it
    as one buries the handful of entries where the two sources really do
    name different machines. Only the base address is compared; a blank on
    one side still counts as a difference, since one source knows the
    server and the other doesn't.
    """
    a_blank, b_blank = is_placeholder(a), is_placeholder(b)
    if a_blank and b_blank:
        return False
    if a_blank != b_blank:
        return True
    return (a or "").split("/", 1)[0].strip().upper() != (b or "").split("/", 1)[0].strip().upper()


def values_differ(a, b):
    """
    True only when the two values genuinely disagree. Comparison is trimmed
    and case-insensitive, and a placeholder ("", "N/A", "-"...) on either
    side counts as "no value": blank vs "N/A" is not a disagreement, but
    blank vs a real value is, because one source knows something the other
    doesn't.
    """
    a_blank, b_blank = is_placeholder(a), is_placeholder(b)
    if a_blank and b_blank:
        return False
    if a_blank != b_blank:
        return True
    return (a or "").strip().upper() != (b or "").strip().upper()


def normalize_service(raw):
    return (raw or "").strip().upper()


def canonical_service(raw):
    norm = normalize_service(raw)
    if not norm:
        return "", False
    canon = SERVICE_ALIASES.get(norm, norm)
    return canon, canon != norm


def host_key_short(raw_host):
    """First label of the name, uppercased - primary_key_comparison.py's form."""
    h = (raw_host or "").strip()
    if not h:
        return ""
    if IPV4_RE.match(h):
        return h
    return h.split(".")[0].strip().upper()


def host_key_full(raw_host):
    """The name exactly as recorded, trimmed and uppercased."""
    return (raw_host or "").strip().upper()


def find_host_alias(host_value, ip_value):
    """(naive, resolved) when a role-suffixed name's paired IP field carries
    the clean FQDN of the same host - only used in 'short' key mode."""
    host_key = host_key_short(host_value)
    if not host_key or "_" not in host_key:
        return None
    ip_str = (ip_value or "").strip()
    if not ip_str or IPV4_RE.match(ip_str):
        return None
    ip_key = host_key_short(ip_str)
    if not ip_key:
        return None
    if host_key.split("_", 1)[0] == ip_key:
        return (host_key, ip_key)
    return None


def collect_short_host_keys(sources):
    """Every short host form seen across both exports."""
    keys = set()
    for rows, host_field in sources:
        for row in rows:
            k = host_key_short(row.get(host_field, ""))
            if k:
                keys.add(k)
    return keys


def find_suffix_candidates(all_keys):
    """
    Host names shaped "<something>_SUFFIX" where "<something>" also exists on
    its own as a host name somewhere in the two exports.

    This is the weak spot in keying on a name at all: 'SRV01APP005' and
    'SRV01APP005_WEB' are probably one machine, but nothing in the raw
    data actually says so. build_host_alias_map() only folds such a pair when
    the row's IP column happens to carry the clean FQDN - a coincidence of
    how the export was written, not a rule - so whenever that column holds a
    numeric address instead (or is blank), the suffixed name stays a separate
    key and the pair splits into one ONLY IN NAGIOS plus one ONLY IN LOOKUP
    entry with nothing marking them as related.

    Returns {suffixed_key: bare_key}. Computed and reported every run whether
    or not folding is switched on, so the exposure is always visible instead
    of depending on someone thinking to ask.
    """
    out = {}
    for k in all_keys:
        if "_" not in k:
            continue
        base = k.split("_", 1)[0]
        if base and base != k and base in all_keys:
            out[k] = base
    return out


def build_host_alias_map(sources):
    alias_map = {}
    for rows, host_field, ip_field in sources:
        for row in rows:
            found = find_host_alias(row.get(host_field, ""), row.get(ip_field, ""))
            if found:
                alias_map.setdefault(found[0], found[1])
    return alias_map


def resolve_nagios_server(text_value):
    if not text_value:
        return ""
    m_ip = DIRECT_IP_URL_RE.search(text_value)
    if m_ip:
        return m_ip.group(1)
    m_host = SERVER_HOST_RE.search(text_value)
    if m_host:
        return SERVER_HOST_TO_NAGIOS_IP.get(m_host.group(1).upper(), "")
    return ""


def row_server(row, server_ref_field):
    """Prefer an explicit Nagios Server column, else resolve the URL field."""
    explicit = (row.get("Nagios Server") or "").strip()
    if explicit and EXPLICIT_SERVER_RE.match(explicit):
        return explicit
    return resolve_nagios_server(row.get(server_ref_field, ""))


def server_matches(value, filt):
    if not filt:
        return True
    v, f = (value or "").lower(), filt.lower()
    if "/" in f:
        return v == f
    return v == f or v.startswith(f + "/")


def parse_server_filter(value):
    v = (value or "").strip()
    if not v:
        return ""
    base, _, inst = v.partition("/")
    ip = None
    if IPV4_RE.match(base):
        ip = base if base in SERVER_HOST_TO_NAGIOS_IP.values() else None
    else:
        name = base.upper()
        if not name.endswith(".EXAMPLE.COM"):
            name += ".EXAMPLE.COM"
        ip = SERVER_HOST_TO_NAGIOS_IP.get(name)
    if ip is None:
        sys.exit(f"ERROR: '{base}' is not a recognized Nagios server. Use one of: "
                 f"{', '.join(sorted(SERVER_HOST_TO_NAGIOS_IP))} or its IP, optionally "
                 f"with '/instance' appended (e.g. 'name2/amicus').")
    return f"{ip}/{inst.strip()}" if inst.strip() else ip


# ----------------------------------------------------------------------------
# Indexing
# ----------------------------------------------------------------------------
def build_index(rows, source, key_mode, alias_map):
    """
    Collapse a source's rows to {key: record}, keyed on host+service (or
    IP+service in 'ip' mode). The first row seen for a key supplies its
    values; later rows only fill fields the first left blank, so a key's
    record is the most complete view available without inventing anything.

    Returns (index, stats).
    """
    fields = SOURCE_FIELDS[source]
    idx = OrderedDict()
    stats = {"rows": 0, "no_key": 0, "no_service": 0, "duplicate_rows": 0}
    for row in rows:
        stats["rows"] += 1
        raw_host = (row.get(fields["host"]) or "").strip()
        raw_ip = (row.get(fields["ip"]) or "").strip()

        if key_mode == "ip":
            key_part = "" if is_placeholder(raw_ip) else (
                raw_ip if IPV4_RE.match(raw_ip) else raw_ip.upper())
        elif key_mode == "full":
            key_part = host_key_full(raw_host)
        else:
            k = host_key_short(raw_host)
            key_part = alias_map.get(k, k)
        if not key_part:
            stats["no_key"] += 1
            continue

        raw_service = (row.get(fields["service"]) or "").strip()
        canon, _ = canonical_service(raw_service)
        if not canon:
            stats["no_service"] += 1
            continue

        key = f"{key_part} | {canon}"
        if key in idx:
            stats["duplicate_rows"] += 1
            rec = idx[key]
            for label, ncol, lcol in COMPARE_FIELDS:
                col = ncol if source == "nagios" else lcol
                if is_placeholder(rec[label]):
                    rec[label] = (row.get(col) or "").strip()
            for label, col in CONTEXT_FIELDS[source]:
                if is_placeholder(rec.get(label, "")):
                    rec[label] = (row.get(col) or "").strip()
            continue

        rec = {
            "Key": key,
            "Service (raw)": raw_service,
            "Service": canon,
        }
        for label, ncol, lcol in COMPARE_FIELDS:
            col = ncol if source == "nagios" else lcol
            rec[label] = (row.get(col) or "").strip()
        # Nagios Server gets the same resolution the rest of the toolkit uses
        rec["Nagios Server"] = row_server(row, fields["server_ref"])
        for label, col in CONTEXT_FIELDS[source]:
            rec[label] = (row.get(col) or "").strip()
        idx[key] = rec
    return idx, stats


# ----------------------------------------------------------------------------
# Near misses
# ----------------------------------------------------------------------------
# A NEAR MISS is an entry that failed to match exactly, but whose closest
# counterpart on the other side is similar enough that the two are almost
# certainly the same thing recorded differently - a typo, a truncation, a
# suffix, or a spelling convention. It is a strong hint that the pair should
# be reconciled (usually by fixing one source, or by adding an entry to
# SERVICE_ALIASES), NOT a claim that they already are the same. Nothing in
# the delta buckets changes because of a near miss: a near miss is still
# reported as ONLY IN NAGIOS or ONLY IN LOOKUP, because asserting a match on
# a guess would be worse than leaving a gap visible.
DEFAULT_NEAR_MISS_THRESHOLD = 0.72

NEAR_MISS_COLUMNS = [
    "Kind", "Similarity", "Unmatched In", "Unmatched Key", "Unmatched Host",
    "Unmatched Service", "Nagios Server", "Closest Found In", "Closest Key",
    "Closest Host", "Closest Service", "What Differs", "Why It Is A Near Miss",
]

NEAR_MISS_SERVICE = "SERVICE SPELLING"
NEAR_MISS_HOST = "HOST SPELLING"


def split_key(key):
    """'HOST | SERVICE' -> ('HOST', 'SERVICE')."""
    left, _, right = key.partition(" | ")
    return left, right


def _root(name):
    """Leading label of a host name, before the first '.' and any '_' suffix.
    Used only to narrow near-miss candidates, never to decide a match."""
    base = (name or "").split(".")[0]
    return base.split("_", 1)[0].strip().upper()


def similarity(a, b):
    return difflib.SequenceMatcher(None, (a or "").upper(), (b or "").upper()).ratio()


def find_near_misses(only_nag, only_lkp, nag_idx, lkp_idx, threshold):
    """
    For each unmatched entry, look for the most similar unmatched entry on
    the other side and report it when the pair clears the threshold.

    Two shapes are looked for, each narrowed so this stays cheap rather than
    comparing everything against everything:
      SERVICE SPELLING - identical host part, similar service name
      HOST SPELLING    - identical service, host names sharing a root
    """
    results = []
    sides = [
        ("Nagios", only_nag, "Lookup File", only_lkp),
        ("Lookup File", only_lkp, "Nagios", only_nag),
    ]
    for base_label, base_rows, other_label, other_rows in sides:
        by_host, by_service = {}, {}
        for r in other_rows:
            h, s = split_key(r["Key"])
            by_host.setdefault(h, []).append((s, r))
            by_service.setdefault(s, []).append((h, r))

        for r in base_rows:
            h, s = split_key(r["Key"])

            best = None
            for cand_s, cand_r in by_host.get(h, []):
                ratio = similarity(s, cand_s)
                if ratio >= threshold and (best is None or ratio > best[0]):
                    best = (ratio, NEAR_MISS_SERVICE, cand_r, cand_s, s)
            for cand_h, cand_r in by_service.get(s, []):
                if _root(cand_h) != _root(h) or cand_h == h:
                    continue
                ratio = similarity(h, cand_h)
                if ratio >= threshold and (best is None or ratio > best[0]):
                    best = (ratio, NEAR_MISS_HOST, cand_r, cand_h, h)
            if best is None:
                continue

            ratio, kind, cand_r, cand_val, own_val = best
            if kind == NEAR_MISS_SERVICE:
                differs = (f"service name: {base_label} '{own_val}' vs "
                           f"{other_label} '{cand_val}'")
                why = ("Same host, and the two service names are nearly identical - almost "
                       "certainly one check recorded under two spellings. Add the pair to "
                       "SERVICE_ALIASES, or correct whichever source is wrong.")
            else:
                differs = (f"host name: {base_label} '{own_val}' vs "
                           f"{other_label} '{cand_val}'")
                why = ("Same service, and the two host names share a root but are written "
                       "differently (short vs FQDN, or a role/instance suffix on one side). "
                       "Correct the name in whichever source is out of date.")
            results.append(OrderedDict([
                ("Kind", kind),
                ("Similarity", round(ratio, 3)),
                ("Unmatched In", base_label),
                ("Unmatched Key", r["Key"]),
                ("Unmatched Host", r.get("Host", "")),
                ("Unmatched Service", r.get("Service", "")),
                ("Nagios Server", base_of(r.get("Nagios Server", ""))),
                ("Closest Found In", other_label),
                ("Closest Key", cand_r["Key"]),
                ("Closest Host", cand_r.get("Host", "")),
                ("Closest Service", cand_r.get("Service", "")),
                ("What Differs", differs),
                ("Why It Is A Near Miss", why),
            ]))
    results.sort(key=lambda x: (-x["Similarity"], x["Unmatched Key"]))
    return results


def is_localhost(name):
    return (name or "").strip().upper() in LOCALHOST_NAMES


def apply_localhost_fallback(all_rows, only_nag, only_lkp, counts, max_candidates):
    """
    Reconcile checks that one source files under "localhost" and the other
    files under the real target host.

    Nagios runs remote probes FROM the monitoring box and records them
    against localhost; the Lookup File records the same probe against the
    machine being probed. Keyed on host+service the two can never meet, so
    ONE check is reported twice - once as ONLY IN NAGIOS, once as ONLY IN
    LOOKUP - and both counts are inflated.

    The rule, applied only when one side's host is a localhost name:
      1. host + service matched normally            -> nothing to do
      2. else, look on the other side for a still-unmatched entry with the
         SAME service under any host                -> pair them
      3. else                                       -> leave it as a mismatch

    Step 2 only considers entries that are themselves still unmatched, so a
    localhost entry can never lay claim to a lookup row that already has a
    proper partner. Where the service resolves to more than
    max_candidates possible partners it is left alone: an ambiguous rescue
    is a guess, and a guess recorded as a match is worse than a visible gap.

    Both sides of a pair move out of their exclusive bucket into
    MATCHED VIA LOCALHOST - a bucket of its own rather than folded into
    IDENTICAL, because these matched on service alone and the host
    attribution genuinely differs. Returns the pair list for reporting.
    """
    if max_candidates < 1:
        return []

    by_key_all = {r["Key"]: r for r in all_rows}

    def index_unmatched(rows):
        idx = {}
        for r in rows:
            host, svc = split_key(r["Key"])
            idx.setdefault(svc, []).append((host, r))
        return idx

    nag_by_svc = index_unmatched(only_nag)
    lkp_by_svc = index_unmatched(only_lkp)

    claimed_nag, claimed_lkp, pairs = set(), set(), []

    # side_label, rows whose host is localhost, the other side's index
    for side, rows, other_idx, claimed_self, claimed_other in (
        ("Nagios", only_nag, lkp_by_svc, claimed_nag, claimed_lkp),
        ("Lookup File", only_lkp, nag_by_svc, claimed_lkp, claimed_nag),
    ):
        for r in rows:
            host, svc = split_key(r["Key"])
            if not is_localhost(host) or r["Key"] in claimed_self:
                continue
            candidates = [(h, cr) for h, cr in other_idx.get(svc, [])
                          if cr["Key"] not in claimed_other and not is_localhost(h)]
            if not candidates or len(candidates) > max_candidates:
                continue
            other_host, other_row = candidates[0]
            claimed_self.add(r["Key"])
            claimed_other.add(other_row["Key"])
            pairs.append(OrderedDict([
                ("Service", svc),
                ("Localhost Side", side),
                ("Localhost Key", r["Key"]),
                ("Counterpart Key", other_row["Key"]),
                ("Counterpart Host", other_host),
                ("Candidates Considered", len(candidates)),
                ("Why", f"{side} files this check under 'localhost' because it runs from the "
                        f"monitoring server; the other source attributes it to the target host "
                        f"'{other_host}'. Same service, so this is one check counted twice, not "
                        f"two gaps."),
            ]))

    if not pairs:
        return []

    # Move both sides out of their exclusive buckets.
    moved = claimed_nag | claimed_lkp
    only_nag[:] = [r for r in only_nag if r["Key"] not in claimed_nag]
    only_lkp[:] = [r for r in only_lkp if r["Key"] not in claimed_lkp]
    for key in moved:
        row = by_key_all.get(key)
        if row is None:
            continue
        row["Delta"] = BUCKET_LOCALHOST
        row["Matched"] = "Yes"
    counts[BUCKET_ONLY_NAGIOS] -= len(claimed_nag)
    counts[BUCKET_ONLY_LOOKUP] -= len(claimed_lkp)
    counts[BUCKET_LOCALHOST] = counts.get(BUCKET_LOCALHOST, 0) + len(moved)
    return pairs


def build_unmatched_service_counts(only_nag, only_lkp, near_misses):
    """
    Which services are actually driving the unmatched entries.

    A raw "N only in Nagios" total says nothing about why. If most of
    those are one service - every host reporting UPTIME that the Lookup File
    simply doesn't track - that is one decision to make, not N problems
    to work through. This groups every ONLY IN NAGIOS / ONLY IN LOOKUP entry
    by its service so that shape is visible at a glance, with a running
    share of the total so it is obvious where the bulk sits.
    """
    nm_keys = {nm["Unmatched Key"] for nm in near_misses}
    per = {}
    for rows, side in ((only_nag, "Only In Nagios"), (only_lkp, "Only In Lookup")):
        for r in rows:
            svc = r.get("Service", "") or "(none)"
            slot = per.setdefault(svc, {"Only In Nagios": 0, "Only In Lookup": 0, "Near Misses": 0})
            slot[side] += 1
            if r["Key"] in nm_keys:
                slot["Near Misses"] += 1

    total = sum(v["Only In Nagios"] + v["Only In Lookup"] for v in per.values()) or 1
    ordered = sorted(per.items(),
                     key=lambda kv: -(kv[1]["Only In Nagios"] + kv[1]["Only In Lookup"]))
    out, running = [], 0
    for svc, v in ordered:
        unmatched = v["Only In Nagios"] + v["Only In Lookup"]
        running += unmatched
        out.append(OrderedDict([
            ("Service", svc),
            ("Unmatched Entries", unmatched),
            ("Only In Nagios", v["Only In Nagios"]),
            ("Only In Lookup", v["Only In Lookup"]),
            ("Near Misses", v["Near Misses"]),
            ("Share Of All Unmatched", f"{unmatched / total * 100:.1f}%"),
            ("Running Share", f"{running / total * 100:.1f}%"),
        ]))
    return out


# ----------------------------------------------------------------------------
# Delta
# ----------------------------------------------------------------------------
def compute_delta(nag_idx, lkp_idx, ignore_fields, server_filter):
    """
    Bucket every key and, for keys in both, diff the comparable fields.
    Returns (all_rows, only_nagios, only_lookup, changed_rows, counts).
    """
    compare = [f for f in COMPARE_FIELDS if f[0] not in ignore_fields]
    all_rows, only_nag, only_lkp, changed = [], [], [], []
    counts = OrderedDict([(BUCKET_ONLY_NAGIOS, 0), (BUCKET_ONLY_LOOKUP, 0),
                          (BUCKET_CHANGED, 0), (BUCKET_IDENTICAL, 0)])
    field_counts = OrderedDict((f[0], 0) for f in compare)

    for key in sorted(set(nag_idx) | set(lkp_idx)):
        n, l = nag_idx.get(key), lkp_idx.get(key)
        srv = (n or l).get("Nagios Server", "")
        if server_filter and not server_matches(srv, server_filter):
            continue

        if n and not l:
            counts[BUCKET_ONLY_NAGIOS] += 1
            row = OrderedDict([("Key", key), ("Delta", BUCKET_ONLY_NAGIOS),
                               ("Service", n["Service"])])
            for label, _, _ in COMPARE_FIELDS:
                row[label] = n[label]
            for label, _ in CONTEXT_FIELDS["nagios"]:
                row[label] = n.get(label, "")
            only_nag.append(row)
            all_rows.append(OrderedDict([("Key", key), ("Delta", BUCKET_ONLY_NAGIOS),
                                         ("Differing Fields", ""),
                                         ("Nagios Server", n["Nagios Server"]),
                                         ("Server (Nagios)", n["Nagios Server"]),
                                         ("Server (Lookup)", ""),
                                         ("Host", n["Host"]), ("Service", n["Service"])]))
        elif l and not n:
            counts[BUCKET_ONLY_LOOKUP] += 1
            row = OrderedDict([("Key", key), ("Delta", BUCKET_ONLY_LOOKUP),
                               ("Service", l["Service"])])
            for label, _, _ in COMPARE_FIELDS:
                row[label] = l[label]
            for label, _ in CONTEXT_FIELDS["lookup"]:
                row[label] = l.get(label, "")
            only_lkp.append(row)
            all_rows.append(OrderedDict([("Key", key), ("Delta", BUCKET_ONLY_LOOKUP),
                                         ("Differing Fields", ""),
                                         ("Nagios Server", l["Nagios Server"]),
                                         ("Server (Nagios)", ""),
                                         ("Server (Lookup)", l["Nagios Server"]),
                                         ("Host", l["Host"]), ("Service", l["Service"])]))
        else:
            diffs = [label for label, _, _ in compare
                     if (servers_differ if label == "Nagios Server" else values_differ)(
                         n[label], l[label])]
            if diffs:
                counts[BUCKET_CHANGED] += 1
                for label in diffs:
                    field_counts[label] += 1
                    changed.append(OrderedDict([
                        ("Key", key),
                        ("Service", n["Service"]),
                        # Server columns so this tab can be sliced the same
                        # way the Summary groups things - without them the
                        # only way to look at one server's problems was to
                        # cross-reference another tab by hand.
                        ("Nagios Server", base_of(n["Nagios Server"]) or base_of(l["Nagios Server"])),
                        ("Server (Nagios)", n["Nagios Server"]),
                        ("Server (Lookup)", l["Nagios Server"]),
                        ("Server Conflict", "Yes" if (
                            base_of(n["Nagios Server"]) and base_of(l["Nagios Server"])
                            and base_of(n["Nagios Server"]) != base_of(l["Nagios Server"])) else "No"),
                        ("Field", label),
                        ("Nagios Value", n[label]),
                        ("Lookup Value", l[label]),
                        ("Nagios Host", n["Host"]),
                        ("Lookup Host", l["Host"]),
                        # Every field disagreeing for this key, repeated on
                        # each of its rows - lets you filter to entries that
                        # are wrong in more than one way at once.
                        ("All Differing Fields", "; ".join(diffs)),
                        ("Differing Field Count", len(diffs)),
                    ]))
                all_rows.append(OrderedDict([("Key", key), ("Delta", BUCKET_CHANGED),
                                             ("Differing Fields", "; ".join(diffs)),
                                             ("Nagios Server", n["Nagios Server"]),
                                             ("Server (Nagios)", n["Nagios Server"]),
                                             ("Server (Lookup)", l["Nagios Server"]),
                                             ("Host", n["Host"]), ("Service", n["Service"])]))
            else:
                counts[BUCKET_IDENTICAL] += 1
                all_rows.append(OrderedDict([("Key", key), ("Delta", BUCKET_IDENTICAL),
                                             ("Differing Fields", ""),
                                             ("Nagios Server", n["Nagios Server"]),
                                             ("Server (Nagios)", n["Nagios Server"]),
                                             ("Server (Lookup)", l["Nagios Server"]),
                                             ("Host", n["Host"]), ("Service", n["Service"])]))
    return all_rows, only_nag, only_lkp, changed, counts, field_counts


def base_of(server):
    """Physical server, with any '/instance' suffix dropped."""
    return (server or "").split("/", 1)[0].strip()


def build_server_stats(all_rows, near_misses):
    """
    Per physical Nagios server: how the two sources compare for the entries
    that server governs.

    An entry is attributed to a server from whichever side knows it - the
    Nagios side when Nagios has it, otherwise the Lookup side - so an entry
    is counted once, under the server actually responsible for it. Entries
    where neither source resolved a server are grouped under "(unresolved)"
    rather than dropped, since a missing server is itself worth seeing.
    """
    nm_by_key = {}
    for nm in near_misses:
        nm_by_key.setdefault(nm["Unmatched Key"], 0)
        nm_by_key[nm["Unmatched Key"]] += 1

    stats = OrderedDict()

    def slot(server):
        return stats.setdefault(server or "(unresolved)", OrderedDict([
            ("Services Compared", 0),
            ("One-to-One (matched)", 0),
            ("Identical", 0),
            ("Incongruent (changed)", 0),
            ("Only In Nagios", 0),
            ("Only In Lookup", 0),
            ("No Match (either side)", 0),
            ("Near Misses", 0),
            ("Server Conflict", 0),
        ]))

    for row in all_rows:
        n_srv, l_srv = base_of(row.get("Server (Nagios)")), base_of(row.get("Server (Lookup)"))
        server = n_srv or l_srv
        s = slot(server)
        s["Services Compared"] += 1
        delta = row["Delta"]
        if delta in (BUCKET_IDENTICAL, BUCKET_CHANGED):
            s["One-to-One (matched)"] += 1
            if delta == BUCKET_IDENTICAL:
                s["Identical"] += 1
            else:
                s["Incongruent (changed)"] += 1
            if n_srv and l_srv and n_srv != l_srv:
                s["Server Conflict"] += 1
        elif delta == BUCKET_ONLY_NAGIOS:
            s["Only In Nagios"] += 1
            s["No Match (either side)"] += 1
        elif delta == BUCKET_ONLY_LOOKUP:
            s["Only In Lookup"] += 1
            s["No Match (either side)"] += 1
        if nm_by_key.get(row["Key"]):
            s["Near Misses"] += 1

    return OrderedDict(sorted(stats.items()))


def build_server_crosstab(all_rows):
    """
    For entries BOTH sources have: which Nagios server does each side think
    the entry belongs to? The diagonal is agreement; anything off it is a
    pair of systems monitoring the same thing while disagreeing about where
    it lives, which is exactly the kind of drift a per-source total hides.
    """
    tab = {}
    servers = set()
    for row in all_rows:
        if row["Delta"] not in (BUCKET_IDENTICAL, BUCKET_CHANGED):
            continue
        n, l = base_of(row.get("Server (Nagios)")) or "(none)", \
               base_of(row.get("Server (Lookup)")) or "(none)"
        servers.add(n)
        servers.add(l)
        tab[(n, l)] = tab.get((n, l), 0) + 1
    return tab, sorted(servers)


def build_service_stats(all_rows, near_misses, top_n=None):
    """
    Same breakdown, but per service name rather than per server - answers
    "which checks are consistently mismatched across the estate".
    """
    nm_keys = {nm["Unmatched Key"] for nm in near_misses}
    stats = OrderedDict()
    for row in all_rows:
        svc = row.get("Service", "") or "(none)"
        s = stats.setdefault(svc, OrderedDict([
            ("Services Compared", 0), ("One-to-One (matched)", 0), ("Identical", 0),
            ("Incongruent (changed)", 0), ("Only In Nagios", 0), ("Only In Lookup", 0),
            ("No Match (either side)", 0), ("Near Misses", 0),
        ]))
        s["Services Compared"] += 1
        delta = row["Delta"]
        if delta in (BUCKET_IDENTICAL, BUCKET_CHANGED):
            s["One-to-One (matched)"] += 1
            s["Identical" if delta == BUCKET_IDENTICAL else "Incongruent (changed)"] += 1
        elif delta == BUCKET_ONLY_NAGIOS:
            s["Only In Nagios"] += 1
            s["No Match (either side)"] += 1
        elif delta == BUCKET_ONLY_LOOKUP:
            s["Only In Lookup"] += 1
            s["No Match (either side)"] += 1
        if row["Key"] in nm_keys:
            s["Near Misses"] += 1
    ordered = OrderedDict(sorted(stats.items(), key=lambda kv: -kv[1]["Services Compared"]))
    if top_n:
        ordered = OrderedDict(list(ordered.items())[:top_n])
    return ordered


def build_server_service_stats(all_rows):
    """
    Per server, per service: how much of that server's trouble each service
    accounts for.

    The per-server table answers "which server is in worse shape"; this
    answers the follow-up, "and what exactly is wrong there". Two different
    percentages are given because they answer different questions:
      Share Of Server's Unmatched  - of everything unresolved on this server,
                                     how much is this one service? Tells you
                                     where the bulk sits.
      Service Unmatched Rate       - of this service's entries on this
                                     server, what fraction is unresolved?
                                     Tells you how badly this service is
                                     doing, regardless of how common it is.
    A service can be 60% of a server's problems while only failing 5% of the
    time (it is simply everywhere), or be 2% of the problems while failing
    100% of the time (rare, but completely broken). Ranking on either one
    alone hides the other case.
    """
    per = {}
    for row in all_rows:
        server = base_of(row.get("Server (Nagios)")) or base_of(row.get("Server (Lookup)")) \
                 or "(unresolved)"
        svc = row.get("Service", "") or "(none)"
        slot = per.setdefault((server, svc), {
            "Entries": 0, "Matched": 0, "Identical": 0, "Changed": 0,
            "Only In Nagios": 0, "Only In Lookup": 0})
        slot["Entries"] += 1
        d = row["Delta"]
        if d == BUCKET_IDENTICAL:
            slot["Matched"] += 1
            slot["Identical"] += 1
        elif d == BUCKET_CHANGED:
            slot["Matched"] += 1
            slot["Changed"] += 1
        elif d == BUCKET_ONLY_NAGIOS:
            slot["Only In Nagios"] += 1
        elif d == BUCKET_ONLY_LOOKUP:
            slot["Only In Lookup"] += 1

    # denominator per server: everything unresolved on that server
    server_unmatched = {}
    for (server, _svc), v in per.items():
        server_unmatched[server] = server_unmatched.get(server, 0) + \
            v["Only In Nagios"] + v["Only In Lookup"]

    out = []
    for (server, svc), v in per.items():
        unmatched = v["Only In Nagios"] + v["Only In Lookup"]
        denom = server_unmatched.get(server, 0) or 1
        out.append(OrderedDict([
            ("Nagios Server", server),
            ("Service", svc),
            ("Entries", v["Entries"]),
            ("Matched", v["Matched"]),
            ("Identical", v["Identical"]),
            ("Changed", v["Changed"]),
            ("Only In Nagios", v["Only In Nagios"]),
            ("Only In Lookup", v["Only In Lookup"]),
            ("Unmatched", unmatched),
            ("Share Of Server's Unmatched", f"{unmatched / denom * 100:.1f}%"),
            ("Service Unmatched Rate", f"{unmatched / v['Entries'] * 100:.1f}%"),
        ]))
    out.sort(key=lambda r: (r["Nagios Server"], -r["Unmatched"], r["Service"]))
    return out


def build_service_pairs(only_nag, only_lkp, threshold):
    """
    Service-against-service: which unmatched Nagios service corresponds to
    which unmatched Lookup File service.

    The naive version of this - emit every Nagios service crossed with every
    Lookup service that goes unmatched on the same host - is worse than
    useless. On a host where Nagios lacks CPU_USAGE and the Lookup lacks
    PING-ONLY, it reports "CPU_USAGE <-> PING-ONLY" as though the two were
    related, when all they share is a host. Ranking those by raw host count
    then floats the most COMMON services to the top rather than the most
    RELATED ones, so the genuine correspondences drown.

    What actually distinguishes a real correspondence is exclusivity: if
    Nagios's CHECK_PING is unmatched on 129 hosts and the Lookup's PING-ONLY
    is unmatched on very nearly those same 129 hosts and few others, the two
    are almost certainly one check under two names - regardless of how the
    strings compare. Whereas UPTIME going unmatched on 600 hosts, 24 of which
    also lack PING-ONLY, says nothing: UPTIME is simply everywhere.

    So each pair is scored on association, not co-occurrence:
      Nagios Support   hosts where the Nagios service is unmatched
      Lookup Support   hosts where the Lookup service is unmatched
      Co-occur         hosts where both are
      Nagios->Lookup   of the Nagios service's hosts, the share that also
                       lack the Lookup service
      Lookup->Nagios   the same the other way round
      Association      Jaccard overlap - co-occur / (either one) - which is
                       high only when the two track each other closely in
                       BOTH directions
    Mutual Best marks a pair that is each side's strongest partner, the
    single most reliable signal available here. Spelling similarity is still
    reported and still counts, but it is now one input among several rather
    than the whole basis.
    """
    nag_by_host, lkp_by_host = {}, {}
    for r in only_nag:
        h, s = split_key(r["Key"])
        nag_by_host.setdefault(h, set()).add(s)
    for r in only_lkp:
        h, s = split_key(r["Key"])
        lkp_by_host.setdefault(h, set()).add(s)

    shared = set(nag_by_host) & set(lkp_by_host)
    # Support is counted over shared hosts only - the same population the
    # pairs are drawn from, so the ratios stay comparable.
    support_n, support_l, pairs = {}, {}, {}
    for host in shared:
        for ns in nag_by_host[host]:
            support_n[ns] = support_n.get(ns, 0) + 1
        for ls in lkp_by_host[host]:
            support_l[ls] = support_l.get(ls, 0) + 1
        for ns in nag_by_host[host]:
            for ls in lkp_by_host[host]:
                slot = pairs.setdefault((ns, ls), set())
                slot.add(host)

    scored = {}
    for (ns, ls), hosts in pairs.items():
        co = len(hosts)
        sn, sl = support_n[ns], support_l[ls]
        conf_n = co / sn if sn else 0.0
        conf_l = co / sl if sl else 0.0
        jac = co / (sn + sl - co) if (sn + sl - co) else 0.0
        scored[(ns, ls)] = (co, sn, sl, conf_n, conf_l, jac, sorted(hosts)[0])

    # Each side's strongest partner, by association then volume.
    best_n, best_l = {}, {}
    for (ns, ls), v in scored.items():
        key = (v[5], v[0])
        if ns not in best_n or key > best_n[ns][1]:
            best_n[ns] = (ls, key)
        if ls not in best_l or key > best_l[ls][1]:
            best_l[ls] = (ns, key)

    out = []
    for (ns, ls), (co, sn, sl, conf_n, conf_l, jac, example) in scored.items():
        ratio = similarity(ns, ls)
        mutual = best_n.get(ns, (None,))[0] == ls and best_l.get(ls, (None,))[0] == ns

        if mutual and (jac >= 0.5 or ratio >= threshold) and co >= 3:
            signal = "STRONG"
            reading = (f"Each side's strongest partner, and they track each other closely "
                       f"({jac:.0%} overlap across {co} host(s)). Almost certainly one check "
                       f"the two systems name differently - confirm, then add to "
                       f"SERVICE_ALIASES and these stop being reported.")
        elif ratio >= threshold and co >= 2:
            signal = "STRONG"
            reading = ("Names are nearly identical and they go unmatched on the same hosts - "
                       "the same check under two spellings.")
        elif jac >= 0.3 and co >= 3:
            signal = "WORTH CHECKING"
            reading = (f"Names differ, but {conf_n:.0%} of this Nagios service's unmatched hosts "
                       f"also lack the Lookup service, and {conf_l:.0%} the other way. That "
                       f"two-way consistency is the evidence - worth confirming they are the "
                       f"same check.")
        elif mutual and co >= 2:
            signal = "WORTH CHECKING"
            reading = ("Each side's strongest partner, but the overlap is loose. Could be a "
                       "correspondence, could be that neither has a better candidate.")
        else:
            signal = "WEAK"
            reading = (f"Low association ({jac:.0%}) - these two are unmatched on {co} shared "
                       f"host(s) but otherwise go their own ways. Most likely unrelated checks "
                       f"that happen to be missing on the same busy hosts, not a naming problem.")

        out.append(OrderedDict([
            ("Nagios Service", ns),
            ("Lookup Service", ls),
            ("Signal", signal),
            ("Mutual Best", "Yes" if mutual else "No"),
            ("Association", round(jac, 3)),
            ("Co-occur Hosts", co),
            ("Nagios Support", sn),
            ("Lookup Support", sl),
            ("Nagios->Lookup", f"{conf_n * 100:.0f}%"),
            ("Lookup->Nagios", f"{conf_l * 100:.0f}%"),
            ("Name Similarity", round(ratio, 3)),
            ("Likely Relationship", reading),
            ("Example Host", example),
        ]))
    rank = {"STRONG": 0, "WORTH CHECKING": 1, "WEAK": 2}
    out.sort(key=lambda r: (rank[r["Signal"]], -r["Association"], -r["Co-occur Hosts"]))
    return out


def build_service_side_by_side(all_rows):
    """Per service: how many entries each source has, and how they resolve."""
    per = {}
    for row in all_rows:
        svc = row.get("Service", "") or "(none)"
        slot = per.setdefault(svc, {"nag": 0, "lkp": 0, "matched": 0,
                                    "only_nag": 0, "only_lkp": 0, "changed": 0})
        d = row["Delta"]
        if d in (BUCKET_IDENTICAL, BUCKET_CHANGED):
            slot["nag"] += 1
            slot["lkp"] += 1
            slot["matched"] += 1
            if d == BUCKET_CHANGED:
                slot["changed"] += 1
        elif d == BUCKET_ONLY_NAGIOS:
            slot["nag"] += 1
            slot["only_nag"] += 1
        elif d == BUCKET_ONLY_LOOKUP:
            slot["lkp"] += 1
            slot["only_lkp"] += 1

    out = []
    for svc, v in per.items():
        out.append(OrderedDict([
            ("Service", svc),
            ("Entries In Nagios", v["nag"]),
            ("Entries In Lookup", v["lkp"]),
            ("Difference (Nagios - Lookup)", v["nag"] - v["lkp"]),
            ("Matched", v["matched"]),
            ("Of Those, Changed", v["changed"]),
            ("Only In Nagios", v["only_nag"]),
            ("Only In Lookup", v["only_lkp"]),
            ("Match Rate", f"{v['matched'] / max(v['nag'] + v['lkp'] - v['matched'], 1) * 100:.1f}%"),
        ]))
    out.sort(key=lambda r: -(r["Only In Nagios"] + r["Only In Lookup"]))
    return out


def write_csv(output_dir, name, rows, columns):
    path = os.path.join(output_dir, name)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return path


# ----------------------------------------------------------------------------
# XLSX
# ----------------------------------------------------------------------------
def write_xlsx(xlsx_path, sheets, counts, field_counts, key_mode, stale_files,
               max_age_hours, ignore_fields, index_stats, server_stats, crosstab,
               crosstab_servers, service_stats, near_misses, threshold,
               unmatched_service_counts, service_count_limit,
               suffix_candidates, unfolded_suffixes, folded_suffixes,
               service_side_by_side, localhost_max_candidates):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    HEADER_FONT = Font(name="Arial", size=11, bold=True, color="FFFFFF")
    HEADER_FILL = PatternFill("solid", fgColor="305496")
    BODY = Font(name="Arial", size=10)
    THIN = Side(style="thin", color="BFBFBF")
    BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
    FILLS = {
        BUCKET_ONLY_NAGIOS: PatternFill("solid", fgColor="FCE4D6"),
        BUCKET_ONLY_LOOKUP: PatternFill("solid", fgColor="DDEBF7"),
        BUCKET_CHANGED: PatternFill("solid", fgColor="FFF2CC"),
        BUCKET_IDENTICAL: PatternFill("solid", fgColor="E2EFDA"),
        BUCKET_LOCALHOST: PatternFill("solid", fgColor="D9E1F2"),
    }

    wb = Workbook()
    wb.remove(wb.active)

    for title, rows, columns in sheets:
        ws = wb.create_sheet(title=title[:31])
        ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=max(len(columns), 1))
        t = ws.cell(row=1, column=1, value=f"{title}  ({len(rows)} row{'s' if len(rows) != 1 else ''})")
        t.font = Font(name="Arial", size=13, bold=True)
        ws.row_dimensions[1].height = 22
        header_row = 2

        # The near-miss tab needs its definition on the tab itself - someone
        # opening it cold has to know what is being claimed, and just as
        # importantly what is NOT being claimed.
        if title == "Per-Server Services":
            blurb = [
                ("One row per server + service: how much of each server's unresolved population "
                 "that service accounts for, and how badly that service itself is doing.", 26),
                ("The two percentages answer different questions and should be read together. "
                 "\"Share Of Server's Unmatched\" is this service's slice of everything "
                 "unresolved on that server - it tells you where the bulk sits. \"Service "
                 "Unmatched Rate\" is the fraction of THIS service's own entries on that server "
                 "that went unresolved - it tells you how badly the service is doing regardless "
                 "of how common it is.", 40),
                ("Why both: a service can be 60% of a server's problems while failing only 5% of "
                 "the time (it is simply everywhere), or 2% of the problems while failing 100% of "
                 "the time (rare, but completely broken). The first is a volume decision, the "
                 "second is a bug. Sorting on either number alone hides the other case.", 40),
            ]
            r_b = 2
            for text, height in blurb:
                ws.merge_cells(start_row=r_b, start_column=1, end_row=r_b, end_column=max(len(columns), 1))
                c = ws.cell(row=r_b, column=1, value=text)
                c.font = Font(name="Arial", size=10, color="404040")
                c.alignment = Alignment(wrap_text=True, vertical="top")
                ws.row_dimensions[r_b].height = height
                r_b += 1
            header_row = r_b + 1

        if title == "Service vs Service":
            blurb = [
                ("Service-against-service, on hosts BOTH sources know about: which unmatched "
                 "Nagios service keeps appearing alongside which unmatched Lookup File service.", 26),
                ("Pairs are scored on ASSOCIATION, not on how often they appear together. "
                 "Merely co-occurring proves nothing: on a host where Nagios lacks CPU_USAGE and "
                 "the Lookup lacks PING-ONLY, the two share a host and nothing else, and ranking "
                 "such pairs by raw count just floats the most COMMON services to the top instead "
                 "of the most RELATED ones.", 40),
                ("What marks a real correspondence is exclusivity - the two tracking each other "
                 "in BOTH directions. \"Nagios->Lookup\" is the share of this Nagios service's "
                 "unmatched hosts that also lack the Lookup service; \"Lookup->Nagios\" is the "
                 "reverse; \"Association\" combines them (overlap over either one), so it is high "
                 "only when both hold. \"Mutual Best\" means each is the other's strongest "
                 "partner - the most reliable signal on this tab.", 46),
                ("Read it this way: high Association with a high name similarity is a spelling "
                 "variant. High Association with a LOW similarity is the valuable case - one "
                 "check the two systems call entirely different things, which no amount of "
                 "string comparison would ever find. Low Association is noise no matter how many "
                 "hosts it spans. Hosts missing from one source entirely are excluded, since a "
                 "machine absent there says nothing about naming.", 46),
                ("The second table below is the plain side-by-side: per service, how many entries "
                 "each source holds and how they resolve. A large \"Difference\" with a low match "
                 "rate is a service one system tracks and the other does not.", 30),
            ]
            r_b = 2
            for text, height in blurb:
                ws.merge_cells(start_row=r_b, start_column=1, end_row=r_b, end_column=max(len(columns), 1))
                c = ws.cell(row=r_b, column=1, value=text)
                c.font = Font(name="Arial", size=10, color="404040")
                c.alignment = Alignment(wrap_text=True, vertical="top")
                ws.row_dimensions[r_b].height = height
                r_b += 1
            header_row = r_b + 1

        if title == "Localhost Pairs":
            blurb = [
                ("Checks that one source files under \"localhost\" and the other files under the "
                 "real target host - reconciled here so a single check stops being counted as "
                 "two separate gaps.", 26),
                ("Why this happens: Nagios runs remote probes FROM the monitoring box - "
                 "certificate checks, HTTP probes against a URL - and records them against "
                 "localhost. The Lookup File records the same probe against the machine being "
                 "probed. Neither is wrong; they simply disagree about what the \"host\" of a "
                 "remote probe is, and a host+service key can never reconcile that on its own.", 40),
                ("The rule: a localhost entry that finds no host+service match is re-checked "
                 "against the other source's still-UNMATCHED entries by service alone. Only "
                 "unmatched ones are eligible, so a localhost entry can never lay claim to a row "
                 "that already has a proper partner.", 34),
                ("\"Candidates Considered\" is the guard. A service like "
                 "'SRV01WEB009_HTTPS_PORTAL_...' embeds its target and resolves to exactly "
                 "one host, so matching on the service alone is safe. A generic name like UPTIME "
                 "or PING resolves to dozens - and the monitoring server's own uptime check is a "
                 "real, distinct thing, not a duplicate of some other host's. Those are left as "
                 "mismatches on purpose: an ambiguous rescue is a guess, and a guess recorded as "
                 "a match is worse than a visible gap. Raise --localhost-max-candidates to loosen "
                 "it, or --no-localhost-fallback to switch the whole rule off.", 52),
                ("These land in their own MATCHED VIA LOCALHOST bucket rather than being folded "
                 "into IDENTICAL, because they matched on service alone and the host attribution "
                 "genuinely differs between the two sources. Keeping them countable means the "
                 "rule's effect stays reviewable instead of silently improving the numbers.", 40),
            ]
            r_b = 2
            for text, height in blurb:
                ws.merge_cells(start_row=r_b, start_column=1, end_row=r_b, end_column=max(len(columns), 1))
                c = ws.cell(row=r_b, column=1, value=text)
                c.font = Font(name="Arial", size=10, color="404040")
                c.alignment = Alignment(wrap_text=True, vertical="top")
                ws.row_dimensions[r_b].height = height
                r_b += 1
            header_row = r_b + 1

        if title == "Near Misses":
            blurb = [
                (f"What a near miss is: an entry that did NOT match, whose closest counterpart "
                 f"on the other side is similar enough (>= {threshold:.2f} similarity) that the "
                 f"two are almost certainly the same thing recorded differently - a typo, a "
                 f"truncation, a role suffix, or a different spelling convention.", 30),
                ("What it is NOT: a match. Near misses stay in ONLY IN NAGIOS / ONLY IN LOOKUP "
                 "on every other tab, and none of the delta counts change because of them. "
                 "Asserting a match on a resemblance would quietly invent agreement that "
                 "isn't there, so this tab only points - it never decides.", 30),
                ("Two shapes are looked for. SERVICE SPELLING: the host part is identical and "
                 "the two service names are nearly the same (e.g. 'CPU_USAG' vs 'CPU_USAGE'). "
                 "HOST SPELLING: the service is identical and the two host names share a root "
                 "but are written differently (short vs FQDN, or a suffix on one side only).", 30),
                ("What to do with a row here: if it is a service spelling difference that keeps "
                 "recurring, add the pair to SERVICE_ALIASES so it stops being reported at all. "
                 "If it is a one-off, or a host spelling difference, correct whichever source is "
                 "out of date. Each row's last two columns say exactly what differs and why it "
                 "was flagged.", 30),
            ]
            r_b = 2
            for text, height in blurb:
                ws.merge_cells(start_row=r_b, start_column=1, end_row=r_b, end_column=max(len(columns), 1))
                c = ws.cell(row=r_b, column=1, value=text)
                c.font = Font(name="Arial", size=10, color="404040")
                c.alignment = Alignment(wrap_text=True, vertical="top")
                ws.row_dimensions[r_b].height = height
                r_b += 1
            r_b += 1

            # Service counts for everything that failed to match - not just
            # the near misses. A bare "N only in Nagios" count hides whether
            # that is one service repeated across the estate or a genuine
            # scatter, and that distinction decides whether the fix is one
            # decision or hundreds.
            ws.cell(row=r_b, column=1,
                    value="Service counts: what is actually driving the unmatched entries").font = Font(
                name="Arial", size=12, bold=True)
            r_b += 1
            ws.merge_cells(start_row=r_b, start_column=1, end_row=r_b, end_column=max(len(columns), 1))
            c = ws.cell(row=r_b, column=1, value=(
                "Every ONLY IN NAGIOS and ONLY IN LOOKUP entry grouped by service, most-affected "
                "first. \"Running Share\" accumulates down the list, so if the first two or three "
                "rows already reach most of the total, the bulk of the mismatch is a handful of "
                "services rather than a broad problem - one decision to make instead of hundreds "
                "of entries to work through. \"Near Misses\" is how many of that service's "
                "unmatched entries have a suggested counterpart in the table below."))
            c.font = Font(name="Arial", size=10, color="404040")
            c.alignment = Alignment(wrap_text=True, vertical="top")
            ws.row_dimensions[r_b].height = 44
            r_b += 1

            if unmatched_service_counts:
                # Only the head of the list goes on the sheet - the tail is a
                # long thin tail of one-offs, and printing all of it would
                # push the near-miss detail hundreds of rows down where
                # nobody would find it. The remainder is rolled into one
                # line, and the full list is in delta_unmatched_by_service.csv.
                shown = unmatched_service_counts[:service_count_limit]
                rest = unmatched_service_counts[service_count_limit:]
                sc_cols = list(unmatched_service_counts[0].keys())
                for ci, name in enumerate(sc_cols, start=1):
                    c = ws.cell(row=r_b, column=ci, value=name)
                    c.font, c.fill, c.border = HEADER_FONT, HEADER_FILL, BORDER
                    c.alignment = Alignment(vertical="center", wrap_text=True)
                r_b += 1
                for rec in shown:
                    for ci, name in enumerate(sc_cols, start=1):
                        c = ws.cell(row=r_b, column=ci, value=rec[name])
                        c.font, c.border = BODY, BORDER
                        if ci == 1:
                            c.font = Font(name="Arial", size=10, bold=True)
                    r_b += 1
                if rest:
                    tail_unmatched = sum(r["Unmatched Entries"] for r in rest)
                    tail_nag = sum(r["Only In Nagios"] for r in rest)
                    tail_lkp = sum(r["Only In Lookup"] for r in rest)
                    tail_nm = sum(r["Near Misses"] for r in rest)
                    vals = [f"({len(rest)} further service(s), each smaller - full list in "
                            f"delta_unmatched_by_service.csv)",
                            tail_unmatched, tail_nag, tail_lkp, tail_nm, "", "100.0%"]
                    for ci, v in enumerate(vals, start=1):
                        c = ws.cell(row=r_b, column=ci, value=v)
                        c.font = Font(name="Arial", size=10, italic=True)
                        c.fill = PatternFill("solid", fgColor="D9D9D9")
                        c.border = BORDER
                    r_b += 1
            else:
                ws.cell(row=r_b, column=1, value="(nothing unmatched)").font = BODY
                r_b += 1
            r_b += 2

            ws.cell(row=r_b, column=1, value="Near-miss detail").font = Font(
                name="Arial", size=12, bold=True)
            r_b += 1
            if not rows:
                ws.merge_cells(start_row=r_b, start_column=1, end_row=r_b, end_column=max(len(columns), 1))
                c = ws.cell(row=r_b, column=1, value=(
                    f"No near misses at the current threshold ({threshold:.2f}). That is a result, "
                    f"not an empty tab: every unmatched entry's closest counterpart on the other "
                    f"side was too dissimilar to suggest they are the same thing. Re-run with a "
                    f"lower --near-miss-threshold (e.g. 0.60) to cast a wider net, at the cost of "
                    f"weaker suggestions. The service counts above still apply."))
                c.font = Font(name="Arial", size=10, italic=True, color="806000")
                c.alignment = Alignment(wrap_text=True, vertical="top")
                ws.row_dimensions[r_b].height = 44
                r_b += 2
            header_row = r_b
        for ci, name in enumerate(columns, start=1):
            c = ws.cell(row=header_row, column=ci, value=name)
            c.font, c.fill, c.border = HEADER_FONT, HEADER_FILL, BORDER
            c.alignment = Alignment(vertical="center", wrap_text=True)
        for ri, row in enumerate(rows, start=header_row + 1):
            for ci, name in enumerate(columns, start=1):
                c = ws.cell(row=ri, column=ci, value=row.get(name, ""))
                c.font, c.border = BODY, BORDER
                if name == "Delta" and row.get(name) in FILLS:
                    c.fill = FILLS[row[name]]
                if name == "Kind":
                    c.fill = PatternFill("solid", fgColor="FFF2CC")
        for ci, name in enumerate(columns, start=1):
            width = max([len(str(name))] + [len(str(r.get(name, ""))) for r in rows[:400]] or [10])
            ws.column_dimensions[get_column_letter(ci)].width = min(max(width + 2, 10), 60)
        ws.freeze_panes = ws.cell(row=header_row + 1, column=1)
        ws.auto_filter.ref = (f"A{header_row}:{get_column_letter(len(columns))}"
                              f"{header_row + max(len(rows), 1)}")

        if title == "Service vs Service" and service_side_by_side:
            r_s = header_row + max(len(rows), 1) + 3
            ws.cell(row=r_s, column=1,
                    value="Side by side: what each source holds per service").font = Font(
                name="Arial", size=12, bold=True)
            r_s += 1
            sbs_cols = list(service_side_by_side[0].keys())
            for ci, name in enumerate(sbs_cols, start=1):
                c = ws.cell(row=r_s, column=ci, value=name)
                c.font, c.fill, c.border = HEADER_FONT, HEADER_FILL, BORDER
                c.alignment = Alignment(vertical="center", wrap_text=True)
            r_s += 1
            for rec in service_side_by_side[:service_count_limit]:
                for ci, name in enumerate(sbs_cols, start=1):
                    c = ws.cell(row=r_s, column=ci, value=rec[name])
                    c.font, c.border = BODY, BORDER
                    if ci == 1:
                        c.font = Font(name="Arial", size=10, bold=True)
                r_s += 1
            if len(service_side_by_side) > service_count_limit:
                ws.merge_cells(start_row=r_s, start_column=1, end_row=r_s, end_column=len(sbs_cols))
                c = ws.cell(row=r_s, column=1, value=(
                    f"({len(service_side_by_side) - service_count_limit} further service(s) - "
                    f"full list in delta_service_side_by_side.csv)"))
                c.font = Font(name="Arial", size=10, italic=True)
                c.fill = PatternFill("solid", fgColor="D9D9D9")

    s = wb.create_sheet(title="Summary", index=0)
    s.sheet_properties.tabColor = "305496"
    r = 1
    if stale_files:
        s.merge_cells(start_row=r, start_column=1, end_row=r, end_column=6)
        b = s.cell(row=r, column=1,
                   value=f"\u26A0 STALE DATA - source file(s) older than {max_age_hours:g}h - "
                         f"this delta may not reflect current data \u26A0")
        b.font = Font(name="Arial", size=18, bold=True, color="FFFFFF")
        b.fill = PatternFill("solid", fgColor="C00000")
        b.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        s.row_dimensions[r].height = 34
        r += 1
        s.merge_cells(start_row=r, start_column=1, end_row=r, end_column=6)
        d = s.cell(row=r, column=1, value="   |   ".join(
            f"{lab}: {age:.1f}h old ({os.path.basename(p)})" for lab, p, age in stale_files))
        d.font = Font(name="Arial", size=10, bold=True, color="C00000")
        d.alignment = Alignment(horizontal="center", wrap_text=True)
        r += 2

    s.cell(row=r, column=1, value="Lookup File vs Nagios - Delta").font = Font(
        name="Arial", size=14, bold=True); r += 1
    s.cell(row=r, column=1,
           value=f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}  -  keyed on "
                 f"{key_mode} host form + service"
                 + (f"  -  ignoring field(s): {', '.join(sorted(ignore_fields))}"
                    if ignore_fields else "")).font = Font(
        name="Arial", size=10, italic=True, color="666666")
    r += 2

    lines = [
        ("What this shows:", True, None),
        ("Every entry is aligned on host + service across the two exports and lands in exactly "
         "one bucket: ONLY IN NAGIOS (monitored, but nothing in the Lookup File routes alerts "
         "for it), ONLY IN LOOKUP (listed for alerting, but Nagios isn't monitoring it, so the "
         "alert can never fire), CHANGED (present in both, but at least one comparable field "
         "disagrees), or IDENTICAL.", False, 40),
        ("CHANGED is the bucket the presence-based comparison scripts cannot show you. Those "
         "answer \"is this key present, yes or no\", so an entry both sources have reads as a "
         "clean match even when they disagree about its address, its governing server or its "
         "dashboard. Those entries are usually the ones worth fixing, because both systems "
         "believe they are correct. The Changed tab lists them one row per disagreeing field, "
         "with both values side by side.", False, 46),
        ("Compared fields are the ones both exports actually carry: Host (the raw spelling each "
         "source used), IP Address, Nagios Server and Dashboard. Fields only one side has - "
         "Nagios's ping, SNMP, duration and command; the Lookup File's application name and "
         "distribution list - travel through as context on the ONLY IN tabs but are never "
         "reported as a difference, since one side having a column the other lacks is not a "
         "disagreement.", False, 46),
        ("A value that is blank, \"N/A\" or another placeholder counts as \"no value\": blank "
         "against \"N/A\" is not reported as a difference, but blank against a real value is, "
         "because one source knows something the other does not.", False, 34),
        ("Nagios Server is compared on the base address only. The Nagios export tags a "
         "per-instance server's dashboards as \"192.0.2.11/amicus\" where the Lookup File records "
         "the bare \"192.0.2.11\" - the same physical server at two levels of detail, not a "
         "disagreement. Reporting those would bury the entries where the two sources really do "
         "name different machines.", False, 40),
        ("Servers are treated as a field, not a filter. The sibling comparison scripts refuse to "
         "match rows tagged to different physical Nagios servers, which is right for a presence "
         "check. For a delta it would be the wrong shape - a host both sources know but disagree "
         "about the server for is not an add plus a removal, it is one entry with a changed "
         "field, and it is reported that way.", False, 40),
        (f"Host suffixes are the known weak point of keying on a name. "
         f"'SRV01APP005' and 'SRV01APP005_WEB' are probably one machine, but nothing "
         f"in the data says so outright: they are only folded together when the row's IP column "
         f"happens to carry the clean FQDN, which is a quirk of how the export was written "
         f"rather than a rule. When it doesn't, the pair splits into one ONLY IN NAGIOS plus one "
         f"ONLY IN LOOKUP entry that looks like two missing things instead of one naming "
         f"difference. This run found {len(suffix_candidates)} suffixed name(s) whose bare form "
         f"also exists; {len(suffix_candidates) - len(unfolded_suffixes)} were folded that way "
         f"and {len(unfolded_suffixes)} were "
         + ("also folded because --fold-host-suffixes was passed."
            if folded_suffixes and unfolded_suffixes else
            "left as separate keys - pass --fold-host-suffixes to merge them, or see "
            "delta_suffix_candidates.csv for the full list and decide case by case. It is off by "
            "default because a suffix is not always cosmetic: 'AUTHWS1_SAML' may be a genuinely "
            "different endpoint from 'AUTHWS1', and merging on a naming convention rather than on "
            "evidence would invent agreement."),
         False, 58),
        (f"Localhost is handled specially. Nagios runs remote probes from the monitoring box "
         f"and files them under 'localhost'; the Lookup File attributes the same probe to the "
         f"machine being probed, so one check appears as two gaps - once on each side. An "
         f"unmatched localhost entry is therefore re-checked against the other source's still-"
         f"unmatched entries by service alone, and a pair is moved into its own MATCHED VIA "
         f"LOCALHOST bucket. Only services resolving to at most "
         f"{localhost_max_candidates} counterpart(s) qualify - generic names like UPTIME resolve "
         f"to dozens and are left as mismatches rather than guessed at. See the Localhost Pairs "
         f"tab; --no-localhost-fallback turns it off.", False, 52),
        ("Service names are reconciled before aligning (SERVICE_ALIASES), so ping-only hosts - "
         "\"N/A\" in Nagios, \"PINGONLY\" in the Lookup File - and the known typo variants line "
         "up instead of producing a spurious add and a spurious removal for the same thing.",
         False, 34),
    ]
    for text, is_header, height in lines:
        s.merge_cells(start_row=r, start_column=1, end_row=r, end_column=6)
        c = s.cell(row=r, column=1, value=text)
        c.font = Font(name="Arial", size=11, bold=True) if is_header else Font(
            name="Arial", size=10, color="404040")
        c.alignment = Alignment(wrap_text=True, vertical="top")
        s.row_dimensions[r].height = height or (15 if is_header else 28)
        r += 1
    r += 1

    s.cell(row=r, column=1, value="Buckets").font = Font(name="Arial", size=11, bold=True); r += 1
    for ci, h in enumerate(["Bucket", "Entries"], start=1):
        c = s.cell(row=r, column=ci, value=h); c.font, c.fill, c.border = HEADER_FONT, HEADER_FILL, BORDER
    r += 1
    for bucket, n in counts.items():
        s.cell(row=r, column=1, value=bucket).font = BODY
        s.cell(row=r, column=2, value=n).font = BODY
        s.cell(row=r, column=1).fill = FILLS.get(bucket, PatternFill())
        for ci in (1, 2):
            s.cell(row=r, column=ci).border = BORDER
        r += 1
    r += 1

    s.cell(row=r, column=1, value="Which fields disagree (CHANGED entries)").font = Font(
        name="Arial", size=11, bold=True); r += 1
    for ci, h in enumerate(["Field", "Entries disagreeing"], start=1):
        c = s.cell(row=r, column=ci, value=h); c.font, c.fill, c.border = HEADER_FONT, HEADER_FILL, BORDER
    r += 1
    for field, n in field_counts.items():
        s.cell(row=r, column=1, value=field).font = BODY
        s.cell(row=r, column=2, value=n).font = BODY
        for ci in (1, 2):
            s.cell(row=r, column=ci).border = BORDER
        r += 1
    r += 1

    # ---- Server-to-server ----
    s.cell(row=r, column=1, value="Server-to-server: Nagios vs Lookup File, per Nagios server").font = Font(
        name="Arial", size=12, bold=True); r += 1
    for text in [
        "Each entry is counted once, under the server responsible for it - the Nagios side's "
        "server when Nagios has the entry, otherwise the Lookup File's. \"One-to-One\" is entries "
        "both sources have (Identical + Incongruent); \"No Match\" is entries only one side has, "
        "broken out by which side. \"Server Conflict\" counts matched entries where the two "
        "sources name DIFFERENT physical servers - both are monitoring it, they just disagree "
        "about where it lives.",
    ]:
        s.merge_cells(start_row=r, start_column=1, end_row=r, end_column=10)
        c = s.cell(row=r, column=1, value=text)
        c.font = Font(name="Arial", size=10, color="404040")
        c.alignment = Alignment(wrap_text=True, vertical="top")
        s.row_dimensions[r].height = 40
        r += 1
    srv_cols = ["Nagios Server"] + list(next(iter(server_stats.values())).keys()) if server_stats else ["Nagios Server"]
    for ci, h in enumerate(srv_cols, start=1):
        c = s.cell(row=r, column=ci, value=h)
        c.font, c.fill, c.border = HEADER_FONT, HEADER_FILL, BORDER
        c.alignment = Alignment(vertical="center", wrap_text=True)
    r += 1
    totals = OrderedDict((k, 0) for k in (srv_cols[1:] or []))
    for server, st in server_stats.items():
        s.cell(row=r, column=1, value=server).font = Font(name="Arial", size=10, bold=True)
        s.cell(row=r, column=1).border = BORDER
        for ci, (k, v) in enumerate(st.items(), start=2):
            c = s.cell(row=r, column=ci, value=v); c.font, c.border = BODY, BORDER
            totals[k] += v
        r += 1
    if server_stats:
        s.cell(row=r, column=1, value="ALL SERVERS").font = Font(name="Arial", size=10, bold=True)
        s.cell(row=r, column=1).fill = PatternFill("solid", fgColor="D9D9D9")
        s.cell(row=r, column=1).border = BORDER
        for ci, (k, v) in enumerate(totals.items(), start=2):
            c = s.cell(row=r, column=ci, value=v)
            c.font = Font(name="Arial", size=10, bold=True)
            c.fill = PatternFill("solid", fgColor="D9D9D9"); c.border = BORDER
        r += 2

    # ---- Server cross-tab ----
    s.cell(row=r, column=1, value="Where the two sources place the same entry").font = Font(
        name="Arial", size=12, bold=True); r += 1
    s.merge_cells(start_row=r, start_column=1, end_row=r, end_column=10)
    c = s.cell(row=r, column=1, value=(
        "Matched entries only (present in both), counted by the server EACH source assigns. "
        "The diagonal is agreement. Anything off the diagonal is the two systems monitoring the "
        "same host+service while disagreeing about which physical Nagios server governs it - the "
        "drift a per-source total cannot show you. Rows are the Nagios side, columns the Lookup "
        "File side."))
    c.font = Font(name="Arial", size=10, color="404040")
    c.alignment = Alignment(wrap_text=True, vertical="top")
    s.row_dimensions[r].height = 40
    r += 1
    hdr = s.cell(row=r, column=1, value="Nagios \\ Lookup")
    hdr.font, hdr.fill, hdr.border = HEADER_FONT, HEADER_FILL, BORDER
    for ci, col_srv in enumerate(crosstab_servers, start=2):
        c = s.cell(row=r, column=ci, value=col_srv)
        c.font, c.fill, c.border = HEADER_FONT, HEADER_FILL, BORDER
    r += 1
    for row_srv in crosstab_servers:
        c = s.cell(row=r, column=1, value=row_srv)
        c.font, c.border = Font(name="Arial", size=10, bold=True), BORDER
        for ci, col_srv in enumerate(crosstab_servers, start=2):
            n = crosstab.get((row_srv, col_srv), 0)
            cell = s.cell(row=r, column=ci, value=n)
            cell.font, cell.border = BODY, BORDER
            if n:
                cell.fill = PatternFill("solid", fgColor=(
                    "E2EFDA" if row_srv == col_srv else "F8D7D7"))
        r += 1
    r += 1

    # ---- Optional per-service breakdown ----
    if service_stats:
        s.cell(row=r, column=1, value="Per-service breakdown").font = Font(
            name="Arial", size=12, bold=True); r += 1
        s.merge_cells(start_row=r, start_column=1, end_row=r, end_column=10)
        c = s.cell(row=r, column=1, value=(
            "The same counts grouped by service name instead of by server - which checks are "
            "consistently mismatched across the estate, rather than which server they sit on. "
            "Shown because --service-breakdown was passed."))
        c.font = Font(name="Arial", size=10, color="404040")
        c.alignment = Alignment(wrap_text=True, vertical="top")
        s.row_dimensions[r].height = 28
        r += 1
        svc_cols = ["Service"] + list(next(iter(service_stats.values())).keys())
        for ci, h in enumerate(svc_cols, start=1):
            c = s.cell(row=r, column=ci, value=h)
            c.font, c.fill, c.border = HEADER_FONT, HEADER_FILL, BORDER
            c.alignment = Alignment(vertical="center", wrap_text=True)
        r += 1
        for svc, st in service_stats.items():
            s.cell(row=r, column=1, value=svc).font = Font(name="Arial", size=10, bold=True)
            s.cell(row=r, column=1).border = BORDER
            for ci, (k, v) in enumerate(st.items(), start=2):
                c = s.cell(row=r, column=ci, value=v); c.font, c.border = BODY, BORDER
            r += 1
        r += 1

    s.cell(row=r, column=1, value="Rows read / skipped per source").font = Font(
        name="Arial", size=11, bold=True); r += 1
    for ci, h in enumerate(["Source", "Rows", "Skipped (no key)", "Skipped (no service)",
                            "Extra rows folded into an existing key"], start=1):
        c = s.cell(row=r, column=ci, value=h); c.font, c.fill, c.border = HEADER_FONT, HEADER_FILL, BORDER
    r += 1
    for source, st in index_stats.items():
        vals = [SOURCE_LABELS[source], st["rows"], st["no_key"], st["no_service"],
                st["duplicate_rows"]]
        for ci, v in enumerate(vals, start=1):
            c = s.cell(row=r, column=ci, value=v); c.font, c.border = BODY, BORDER
        r += 1

    s.column_dimensions["A"].width = 42
    for col in "BCDEFGHIJ":
        s.column_dimensions[col].width = 20
    wb.save(xlsx_path)


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Delta between the Lookup File and the Nagios export: added, removed, and changed entries.")
    ap.add_argument("--input-dir", default=DEFAULT_INPUT_DIR,
                    help=f"Directory containing the source CSVs (default: {DEFAULT_INPUT_DIR})")
    ap.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                    help=f"Directory to write outputs (default: {DEFAULT_OUTPUT_DIR})")
    ap.add_argument("--key-mode", choices=("short", "full", "ip"), default="short",
                    help="Which host form to align entries on: 'short' (first label, role "
                         "suffixes folded - the default), 'full' (name exactly as recorded), "
                         "or 'ip' (IP address instead of host name).")
    ap.add_argument("--ignore-field", action="append", default=[], dest="ignore_fields",
                    help="Comparable field to exclude from the CHANGED check (repeatable). "
                         f"Valid: {', '.join(f[0] for f in COMPARE_FIELDS)}")
    ap.add_argument("--nagios-server", default="",
                    help="Restrict output to entries governed by one Nagios server "
                         "(IP or server name, optionally with '/instance').")
    ap.add_argument("--no-localhost-fallback", action="store_true",
                    help="Disable localhost reconciliation. By default, a 'localhost' entry that "
                         "finds no host+service match is re-checked against the other source's "
                         "unmatched entries by SERVICE alone, because Nagios files remote probes "
                         "under localhost while the Lookup File attributes them to the target "
                         "host - so one check would otherwise be counted as two separate gaps. "
                         "Matches land in their own MATCHED VIA LOCALHOST bucket, never folded "
                         "into IDENTICAL.")
    ap.add_argument("--localhost-max-candidates", type=int,
                    default=DEFAULT_LOCALHOST_MAX_CANDIDATES,
                    help=f"How many possible partners a localhost entry's service may resolve to "
                         f"and still be rescued (default: {DEFAULT_LOCALHOST_MAX_CANDIDATES}). "
                         f"Service names that embed their target resolve to exactly one and are "
                         f"safe; generic names like UPTIME resolve to many and are deliberately "
                         f"left as mismatches rather than guessed at. Raise it only if you want "
                         f"looser, less certain rescues.")
    ap.add_argument("--fold-host-suffixes", action="store_true",
                    help="Also fold 'HOST_SUFFIX' onto 'HOST' whenever the bare HOST exists as a "
                         "host name in either export - independent of what the IP column says. "
                         "Off by default because a suffix is not always cosmetic ('AUTHWS1_SAML' "
                         "may be a genuinely different endpoint from 'AUTHWS1'), so this merges "
                         "on a naming convention rather than on evidence. Candidates are "
                         "reported either way; this only decides whether they are acted on. "
                         "Applies to --key-mode short only.")
    ap.add_argument("--service-breakdown", action="store_true",
                    help="Also break the comparison down per service name in the Summary "
                         "(and write delta_by_service.csv), not just per server.")
    ap.add_argument("--top-services", type=int, default=40,
                    help="With --service-breakdown, how many services to show in the Summary "
                         "table, most-compared first (default: 40; the CSV always has all).")
    ap.add_argument("--near-miss-threshold", type=float, default=DEFAULT_NEAR_MISS_THRESHOLD,
                    help=f"Similarity (0-1) at which an unmatched entry's closest counterpart "
                         f"counts as a near miss (default: {DEFAULT_NEAR_MISS_THRESHOLD}). "
                         f"Raise it for fewer, safer suggestions.")
    ap.add_argument("--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS,
                    help=f"Flag a source file as stale past this age (default: {DEFAULT_MAX_AGE_HOURS}).")
    args = ap.parse_args()

    valid = {f[0] for f in COMPARE_FIELDS}
    bad = [f for f in args.ignore_fields if f not in valid]
    if bad:
        sys.exit(f"ERROR: --ignore-field {bad} not comparable. Valid: {', '.join(sorted(valid))}")
    ignore_fields = set(args.ignore_fields)
    server_filter = parse_server_filter(args.nagios_server)

    os.makedirs(args.output_dir, exist_ok=True)

    paths = {}
    for source in ("nagios", "lookup"):
        paths[source] = find_latest_file(args.input_dir, FILE_PATTERNS[source], SOURCE_LABELS[source])
        print(f"{SOURCE_LABELS[source] + ' file:':22s}{paths[source]}")

    now = datetime.now().timestamp()
    stale_files = []
    for source, path in paths.items():
        age = (now - os.path.getmtime(path)) / 3600
        if age > args.max_age_hours:
            stale_files.append((SOURCE_LABELS[source], path, age))
    if stale_files:
        print(f"\n[WARNING] {len(stale_files)} source file(s) older than {args.max_age_hours}h:")
        for lab, path, age in stale_files:
            print(f"    {lab}: {age:.1f}h old -> {path}")

    raw = {s: read_csv_robust(p) for s, p in paths.items()}

    alias_map = {}
    if args.key_mode == "short":
        alias_map = build_host_alias_map(
            [(raw[s], SOURCE_FIELDS[s]["host"], SOURCE_FIELDS[s]["ip"]) for s in raw])
        if alias_map:
            print(f"\nResolved {len(alias_map)} role-suffixed host alias(es) to their clean hostname")

    # Suffixed names whose bare form also exists. Always computed, because the
    # IP-based alias rule above only catches these by coincidence, and a pair
    # it misses splits silently into two unmatched entries.
    all_host_keys = collect_short_host_keys(
        [(raw[s], SOURCE_FIELDS[s]["host"]) for s in raw])
    suffix_candidates = find_suffix_candidates(all_host_keys)
    unfolded = {k: v for k, v in suffix_candidates.items() if k not in alias_map}
    if suffix_candidates:
        print(f"\nHost names with a '_SUFFIX' whose bare form also exists: "
              f"{len(suffix_candidates)}")
        print(f"  already folded by the IP-based alias rule: "
              f"{len(suffix_candidates) - len(unfolded)}")
        print(f"  NOT folded - these stay separate keys:      {len(unfolded)}")
        for k in sorted(unfolded)[:8]:
            print(f"      {k}  vs  {unfolded[k]}")
        if len(unfolded) > 8:
            print(f"      ... and {len(unfolded) - 8} more (see delta_suffix_candidates.csv)")

    if args.fold_host_suffixes and args.key_mode == "short":
        if unfolded:
            alias_map.update(unfolded)
            print(f"  --fold-host-suffixes: folding those {len(unfolded)} onto their bare name")
    elif args.fold_host_suffixes:
        print("  [WARN] --fold-host-suffixes applies to --key-mode short only; ignored here.")
    elif unfolded:
        print("  (pass --fold-host-suffixes to merge them; left separate by default)")

    print(f"\nAligning entries on: {args.key_mode} host form + service")
    index_stats = OrderedDict()
    idx = {}
    for source in ("nagios", "lookup"):
        idx[source], index_stats[source] = build_index(raw[source], source, args.key_mode, alias_map)
        st = index_stats[source]
        extra = []
        if st["no_key"]:
            extra.append(f"{st['no_key']} skipped - no usable key")
        if st["no_service"]:
            extra.append(f"{st['no_service']} skipped - no service")
        if st["duplicate_rows"]:
            extra.append(f"{st['duplicate_rows']} extra row(s) folded into an existing key")
        note = ("  (" + "; ".join(extra) + ")") if extra else ""
        print(f"  {SOURCE_LABELS[source]:12s} {st['rows']:6d} rows -> {len(idx[source]):5d} entries{note}")

    all_rows, only_nag, only_lkp, changed, counts, field_counts = compute_delta(
        idx["nagios"], idx["lookup"], ignore_fields, server_filter)

    # Runs before near misses and every statistic, so the whole report is
    # built from post-reconciliation buckets rather than double-counting the
    # localhost checks.
    localhost_pairs = []
    if not args.no_localhost_fallback:
        localhost_pairs = apply_localhost_fallback(
            all_rows, only_nag, only_lkp, counts, args.localhost_max_candidates)
        if localhost_pairs:
            n_side = sum(1 for p in localhost_pairs if p["Localhost Side"] == "Nagios")
            print(f"\nLocalhost reconciliation: paired {len(localhost_pairs)} check(s) that one "
                  f"source files under 'localhost' and the other under the target host")
            print(f"  ({n_side} localhost-in-Nagios, {len(localhost_pairs) - n_side} "
                  f"localhost-in-Lookup) - {len(localhost_pairs) * 2} entries moved out of the "
                  f"exclusive buckets into {BUCKET_LOCALHOST}")
        else:
            print("\nLocalhost reconciliation: no unmatched localhost entry had an unambiguous "
                  "counterpart")

    near_misses = find_near_misses(only_nag, only_lkp, idx["nagios"], idx["lookup"],
                                   args.near_miss_threshold)
    # Flags that let the All / Changed tabs be filtered the way the Summary
    # groups things: which entries matched, which have a server conflict, and
    # which have a near-miss suggestion waiting on the Near Misses tab.
    nm_keys = {nm["Unmatched Key"] for nm in near_misses}
    for row in all_rows:
        n_srv, l_srv = base_of(row.get("Server (Nagios)")), base_of(row.get("Server (Lookup)"))
        row["Server Conflict"] = "Yes" if (n_srv and l_srv and n_srv != l_srv) else "No"
        row["Matched"] = "Yes" if row["Delta"] in (BUCKET_IDENTICAL, BUCKET_CHANGED) else "No"
        row["Near Miss"] = "Yes" if row["Key"] in nm_keys else "No"
        row["Differing Field Count"] = (
            len([f for f in row["Differing Fields"].split("; ") if f])
            if row.get("Differing Fields") else 0)
    for row in changed:
        row["Near Miss"] = "Yes" if row["Key"] in nm_keys else "No"

    unmatched_service_counts = build_unmatched_service_counts(only_nag, only_lkp, near_misses)
    server_service_stats = build_server_service_stats(all_rows)
    service_pairs = build_service_pairs(only_nag, only_lkp, args.near_miss_threshold)
    service_side_by_side = build_service_side_by_side(all_rows)
    server_stats = build_server_stats(all_rows, near_misses)
    crosstab, crosstab_servers = build_server_crosstab(all_rows)
    service_stats_full = build_service_stats(all_rows, near_misses)
    service_stats = (build_service_stats(all_rows, near_misses, args.top_services)
                     if args.service_breakdown else None)

    print("\nDelta:")
    for bucket, n in counts.items():
        print(f"  {bucket:16s} {n:6d}")
    if any(field_counts.values()):
        print("\n  Fields disagreeing on CHANGED entries:")
        for field, n in field_counts.items():
            if n:
                print(f"    {field:16s} {n:6d}")

    print(f"\n  Near misses (>= {args.near_miss_threshold:.2f} similarity): {len(near_misses)}")
    kinds = {}
    for nm in near_misses:
        kinds[nm["Kind"]] = kinds.get(nm["Kind"], 0) + 1
    for k, n in sorted(kinds.items()):
        print(f"    {k:18s} {n:6d}")

    print("\nPer server:")
    hdr = f"  {'server':16s}{'compared':>10}{'1-to-1':>9}{'changed':>9}{'only Nag':>10}{'only Lkp':>10}{'near':>7}{'srv conflict':>14}"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for server, st in server_stats.items():
        print(f"  {server:16s}{st['Services Compared']:>10}{st['One-to-One (matched)']:>9}"
              f"{st['Incongruent (changed)']:>9}{st['Only In Nagios']:>10}"
              f"{st['Only In Lookup']:>10}{st['Near Misses']:>7}{st['Server Conflict']:>14}")

    if service_pairs:
        print("\nService vs service - unmatched pairs sharing a host (top 5):")
        for p in service_pairs[:5]:
            print(f"  [{p['Signal']:14}] assoc {p['Association']:>5}  {p['Co-occur Hosts']:4d}/"
                  f"{p['Nagios Support']}-{p['Lookup Support']} hosts  "
                  f"nagios '{p['Nagios Service'][:26]}'  <->  lookup '{p['Lookup Service'][:26]}'")

    print("\nWorst service per server (by share of that server's unmatched):")
    seen = set()
    for rec in server_service_stats:
        if rec["Nagios Server"] in seen or rec["Unmatched"] == 0:
            continue
        seen.add(rec["Nagios Server"])
        # Pulled out into locals first: the key contains an apostrophe, so it
        # can be quoted with neither ' nor " inside an f-string expression on
        # Python < 3.12, where nesting the same quote type is a syntax error.
        share = rec["Share Of Server's Unmatched"]
        rate = rec["Service Unmatched Rate"]
        print(f"  {rec['Nagios Server']:16s} {rec['Service'][:26]:28s} "
              f"{rec['Unmatched']:5d} unmatched  "
              f"{share:>7} of server's problems  "
              f"{rate:>7} of its own entries")

    all_cols = ["Key", "Delta", "Differing Fields", "Differing Field Count", "Nagios Server",
                "Server (Nagios)", "Server (Lookup)", "Server Conflict", "Matched",
                "Near Miss", "Host", "Service"]
    nag_cols = (["Key", "Delta", "Service"] + [f[0] for f in COMPARE_FIELDS]
                + [c[0] for c in CONTEXT_FIELDS["nagios"]])
    lkp_cols = (["Key", "Delta", "Service"] + [f[0] for f in COMPARE_FIELDS]
                + [c[0] for c in CONTEXT_FIELDS["lookup"]])
    chg_cols = ["Key", "Service", "Nagios Server", "Server (Nagios)", "Server (Lookup)",
                "Server Conflict", "Field", "Nagios Value", "Lookup Value",
                "Nagios Host", "Lookup Host", "All Differing Fields", "Differing Field Count",
                "Near Miss"]

    print()
    for name, rows, cols in [
        ("delta_all.csv", all_rows, all_cols),
        ("delta_only_in_nagios.csv", only_nag, nag_cols),
        ("delta_only_in_lookup.csv", only_lkp, lkp_cols),
        ("delta_changed.csv", changed, chg_cols),
        ("delta_near_misses.csv", near_misses, NEAR_MISS_COLUMNS),
        ("delta_by_server_service.csv", server_service_stats,
         list(server_service_stats[0].keys()) if server_service_stats else ["Nagios Server"]),
        ("delta_service_vs_service.csv", service_pairs,
         list(service_pairs[0].keys()) if service_pairs else ["Nagios Service"]),
        ("delta_service_side_by_side.csv", service_side_by_side,
         list(service_side_by_side[0].keys()) if service_side_by_side else ["Service"]),
        ("delta_localhost_pairs.csv", localhost_pairs,
         list(localhost_pairs[0].keys()) if localhost_pairs else
         ["Service", "Localhost Side", "Localhost Key", "Counterpart Key", "Counterpart Host",
          "Candidates Considered", "Why"]),
        ("delta_suffix_candidates.csv",
         [OrderedDict([("Suffixed Host", k), ("Bare Host", v),
                       ("Folded", "Yes" if k in alias_map else "No"),
                       ("How", "IP-column alias rule" if k in alias_map and k not in unfolded
                               else ("--fold-host-suffixes" if k in alias_map else
                                     "not folded - kept as a separate key"))])
          for k, v in sorted(suffix_candidates.items())],
         ["Suffixed Host", "Bare Host", "Folded", "How"]),
        ("delta_unmatched_by_service.csv", unmatched_service_counts,
         list(unmatched_service_counts[0].keys()) if unmatched_service_counts else ["Service"]),
        ("delta_by_server.csv",
         [OrderedDict([("Nagios Server", srv)] + list(st.items())) for srv, st in server_stats.items()],
         ["Nagios Server"] + (list(next(iter(server_stats.values())).keys()) if server_stats else [])),
        ("delta_by_service.csv",
         [OrderedDict([("Service", svc)] + list(st.items())) for svc, st in service_stats_full.items()],
         ["Service"] + (list(next(iter(service_stats_full.values())).keys()) if service_stats_full else [])),
    ]:
        p = write_csv(args.output_dir, name, rows, cols)
        print(f"[{len(rows):6d} rows] -> {p}")

    xlsx_path = os.path.join(args.output_dir, "lookup_nagios_delta.xlsx")
    nm_cols = NEAR_MISS_COLUMNS
    write_xlsx(xlsx_path, [
        ("Only in Nagios", only_nag, nag_cols),
        ("Only in Lookup", only_lkp, lkp_cols),
        ("Changed", changed, chg_cols),
        ("Localhost Pairs", localhost_pairs,
         list(localhost_pairs[0].keys()) if localhost_pairs else
         ["Service", "Localhost Side", "Localhost Key", "Counterpart Key", "Counterpart Host",
          "Candidates Considered", "Why"]),
        ("Near Misses", near_misses, nm_cols),
        ("Per-Server Services", server_service_stats,
         list(server_service_stats[0].keys()) if server_service_stats else ["Nagios Server"]),
        ("Service vs Service", service_pairs,
         list(service_pairs[0].keys()) if service_pairs else
         ["Nagios Service", "Lookup Service", "Hosts Affected", "Similarity",
          "Likely Relationship", "Example Host"]),
        ("All", all_rows, all_cols),
    ], counts, field_counts, args.key_mode, stale_files, args.max_age_hours,
        ignore_fields, index_stats, server_stats, crosstab, crosstab_servers,
        service_stats, near_misses, args.near_miss_threshold, unmatched_service_counts,
        args.top_services, suffix_candidates, unfolded, args.fold_host_suffixes,
        service_side_by_side, args.localhost_max_candidates)
    print(f"\nWorkbook written to {xlsx_path}")


if __name__ == "__main__":
    main()