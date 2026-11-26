"""Signature-based SQL injection detector.

AWS WAF is the primary filter in the cloud. This detector is the second layer:
it classifies every request that reaches the app (so the dashboard can count
normal / suspicious / blocked traffic), and stands in for WAF when the stack
runs locally.

Each rule carries a weight. A request's score is the sum of the weights of the
distinct rules it matched across all inspected fields:
    score >= BLOCK_SCORE      -> "blocked"
    score >= SUSPICIOUS_SCORE -> "suspicious"
    otherwise                 -> "normal"
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote_plus

BLOCK_SCORE = 8
SUSPICIOUS_SCORE = 3
MAX_FIELD_LENGTH = 4096


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern[str]
    weight: int


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


RULES: tuple[Rule, ...] = (
    Rule("SQLI-UNION", "UNION SELECT data extraction",
         _r(r"\bunion\b\s+(?:all\s+|distinct\s+)?\(?\s*select\b"), 10),
    Rule("SQLI-STACKED", "Stacked query after a semicolon",
         _r(r";\s*(?:drop|delete|insert|update|alter|create|truncate|grant|revoke|copy|exec|execute|select)\b"), 10),
    Rule("SQLI-TIME", "Time-based blind injection",
         _r(r"\b(?:pg_sleep|sleep|benchmark)\s*\(|\bwaitfor\s+delay\b"), 10),
    Rule("SQLI-DANGER-FN", "File, command or cross-database function",
         _r(r"\b(?:load_file|xp_cmdshell|lo_import|lo_export|dblink|pg_read_file|pg_ls_dir)\b"
            r"|\binto\s+(?:out|dump)file\b|\bcopy\b.+\b(?:from|to)\s+program\b"), 10),
    Rule("SQLI-SUBQUERY", "Boolean condition with a subquery",
         _r(r"\b(?:and|or)\b\s*\(?\s*select\b"), 9),
    Rule("SQLI-DDL", "Schema-changing statement",
         _r(r"\b(?:drop|alter|truncate)\s+(?:table|database|schema|user|role)\b"), 9),
    Rule("SQLI-ERROR-FN", "Error-based extraction function",
         _r(r"\b(?:extractvalue|updatexml)\s*\(|\bcast\s*\(.+\bas\s+(?:int|integer|numeric)\b"), 8),
    Rule("SQLI-NUMERIC-TAUT", "Always-true numeric condition",
         _r(r"\b(?:or|and)\s+(\d+)\s*=\s*\1\b"), 8),
    Rule("SQLI-SCHEMA", "System catalogue enumeration",
         _r(r"\b(?:information_schema|pg_catalog|pg_shadow|pg_user|pg_roles|pg_tables"
            r"|sqlite_master|sysobjects|mysql\.user)\b"), 8),
    Rule("SQLI-QUOTE-BREAK", "Quote closed then SQL resumed",
         _r(r"['\"`]\s*(?:\)\s*)*(?:\b(?:or|and|union|having|order\s+by|group\s+by)\b|;|--|#|/\*|\|\|)"), 6),
    Rule("SQLI-TAUTOLOGY", "Always-true string condition",
         _r(r"\b(?:or|and)\b\s*(['\"]?)(\w+)\1\s*(?:=|like)\s*['\"]?\2\b"
            r"|\b(?:or|and)\b\s*''\s*=\s*'|\bor\s+true\b"), 6),
    Rule("SQLI-COMMENT", "Trailing SQL comment",
         _r(r"(?:--|#)\s*$|/\*.*?\*/"), 3),
    Rule("SQLI-SELECT-FROM", "SELECT ... FROM fragment",
         _r(r"\bselect\b.+\bfrom\b"), 5),
    Rule("SQLI-STRING-FN", "String / encoding function often used in payloads",
         _r(r"\b(?:char|chr|ascii|substr|substring|concat|hex|unhex|md5|version|current_user)\s*\("), 3),
    Rule("SQLI-HEX", "Long hex literal",
         _r(r"\b0x[0-9a-f]{6,}\b"), 3),
    Rule("SCANNER-UA", "Known SQL injection tool user agent",
         _r(r"\b(?:sqlmap|havij|sqlninja|bbqsql|jsql|nosqlmap)\b"), 4),
)

RULES_BY_ID = {r.id: r for r in RULES}


@dataclass
class Match:
    rule_id: str
    field: str
    snippet: str
    decoded: bool = False   # the value only matched after URL/Unicode decoding


@dataclass
class Inspection:
    score: int = 0
    verdict: str = "normal"
    matches: list[Match] = field(default_factory=list)

    @property
    def rule_ids(self) -> list[str]:
        seen: list[str] = []
        for m in self.matches:
            if m.rule_id not in seen:
                seen.append(m.rule_id)
        return seen

    @property
    def sample(self) -> str | None:
        """The input that scored highest, for the dashboard (truncated)."""
        if not self.matches:
            return None
        best = max(self.matches, key=lambda m: RULES_BY_ID[m.rule_id].weight)
        return f"{best.field}: {best.snippet}"[:300]


def normalise(value: str) -> str:
    """Undo the common evasion layers before matching.

    URL-decoding repeats (double-encoded payloads), Unicode is folded to its
    compatibility form (full-width quotes become ASCII), inline /**/ comments
    used as whitespace are collapsed, and runs of whitespace are squeezed.
    """
    text = value[:MAX_FIELD_LENGTH]
    for _ in range(3):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("\x00", "")
    text = re.sub(r"/\*!?\d*", " /*", text)          # MySQL versioned comments
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _was_decoded(raw: str, normalised: str) -> bool:
    """True when URL-decoding or Unicode folding changed the value, beyond
    whitespace: the payload was encoded to slip past naive filters."""
    plain = re.sub(r"\s+", " ", raw[:MAX_FIELD_LENGTH].replace("+", " ")).strip()
    return plain != normalised and "%" in raw or unicodedata.normalize("NFKC", raw) != raw


def _strip_inline_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)


def inspect_fields(
    fields: list[tuple[str, str]], disabled: frozenset[str] | set[str] = frozenset()
) -> Inspection:
    """Score a request from (field name, raw value) pairs.

    `disabled` holds rule IDs an administrator switched off; they are skipped.
    Scoring and thresholds are otherwise unchanged.
    """
    result = Inspection()
    matched_rules: set[str] = set()

    for name, raw in fields:
        if not raw:
            continue
        text = normalise(raw)
        if not text:
            continue
        decoded = _was_decoded(raw, text)
        variants = {text, _strip_inline_comments(text)}
        for rule in RULES:
            if rule.id in matched_rules or rule.id in disabled:
                continue
            if rule.id == "SCANNER-UA" and name != "header:user-agent":
                continue
            if rule.id != "SCANNER-UA" and name == "header:user-agent":
                continue
            for variant in variants:
                if rule.pattern.search(variant):
                    matched_rules.add(rule.id)
                    result.matches.append(Match(rule.id, name, text[:200], decoded))
                    break

    result.score = sum(RULES_BY_ID[r].weight for r in matched_rules)
    if result.score >= BLOCK_SCORE:
        result.verdict = "blocked"
    elif result.score >= SUSPICIOUS_SCORE:
        result.verdict = "suspicious"
    return result


def flatten_json(value: object, prefix: str = "body") -> list[tuple[str, str]]:
    """Turn a parsed JSON body into (field, string) pairs, keys included."""
    out: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for k, v in value.items():
            key = str(k)
            out.append((f"{prefix}.key", key))
            out.extend(flatten_json(v, f"{prefix}.{key}"))
    elif isinstance(value, list):
        for i, v in enumerate(value[:200]):
            out.extend(flatten_json(v, f"{prefix}[{i}]"))
    elif isinstance(value, str):
        out.append((prefix, value))
    return out


# ---------------------------------------------------------------- metadata
# Descriptive data for the console. It does not influence scoring.

CATEGORY_LABELS = {
    "union": "UNION-based injection",
    "boolean": "Boolean-based injection",
    "comment": "Comment-based injection",
    "time": "Time-based injection",
    "auth_bypass": "Authentication bypass attempt",
    "catalogue": "System catalogue enumeration",
    "encoded": "Encoded SQL injection",
    "stacked": "Stacked query injection",
    "error": "Error-based injection",
    "basic": "Basic SQL injection",
    "scanner": "Automated scanner",
}

RULE_INFO: dict[str, dict[str, str]] = {
    "SQLI-UNION": {"category": "union", "severity": "critical",
        "explanation": "The input contains UNION SELECT, which appends a second query to the original one "
                       "so its rows (often from another table) come back in the response."},
    "SQLI-STACKED": {"category": "stacked", "severity": "critical",
        "explanation": "A semicolon followed by a new statement tries to run a second, separate SQL command "
                       "such as DROP, DELETE or INSERT."},
    "SQLI-TIME": {"category": "time", "severity": "high",
        "explanation": "A sleep or delay function lets an attacker infer data one yes/no question at a time "
                       "by measuring how long the response takes."},
    "SQLI-DANGER-FN": {"category": "stacked", "severity": "critical",
        "explanation": "Functions that read files, run operating-system commands or reach other databases "
                       "go far beyond reading data."},
    "SQLI-SUBQUERY": {"category": "boolean", "severity": "high",
        "explanation": "AND/OR followed by a subquery asks the database a true/false question about data the "
                       "user should not see (boolean blind injection)."},
    "SQLI-DDL": {"category": "stacked", "severity": "critical",
        "explanation": "DROP, ALTER or TRUNCATE would change or destroy the schema."},
    "SQLI-ERROR-FN": {"category": "error", "severity": "high",
        "explanation": "Functions that force a database error whose message contains data (error-based "
                       "extraction)."},
    "SQLI-NUMERIC-TAUT": {"category": "boolean", "severity": "high",
        "explanation": "OR 1=1 style conditions are always true, so a WHERE clause would match every row."},
    "SQLI-SCHEMA": {"category": "catalogue", "severity": "high",
        "explanation": "References to information_schema or pg_catalog map out the database's tables and "
                       "columns, the usual first step before extracting data."},
    "SQLI-QUOTE-BREAK": {"category": "basic", "severity": "medium",
        "explanation": "A quote closes the application's string literal and SQL keywords or comment markers "
                       "follow, so the rest of the input would run as SQL."},
    "SQLI-TAUTOLOGY": {"category": "boolean", "severity": "medium",
        "explanation": "A condition like 'a'='a' is always true and is used to bypass checks such as "
                       "password comparisons."},
    "SQLI-COMMENT": {"category": "comment", "severity": "low",
        "explanation": "A trailing -- or # comments out the rest of the application's query, for example the "
                       "password check after a username."},
    "SQLI-SELECT-FROM": {"category": "union", "severity": "medium",
        "explanation": "A SELECT ... FROM fragment inside a value usually means a query is being smuggled in."},
    "SQLI-STRING-FN": {"category": "encoded", "severity": "low",
        "explanation": "CHAR(), CONCAT(), SUBSTRING() and similar functions build strings piece by piece, "
                       "typically to avoid writing a suspicious keyword literally."},
    "SQLI-HEX": {"category": "encoded", "severity": "low",
        "explanation": "A long hex literal (0x...) can spell out strings without quotes, a common filter "
                       "evasion."},
    "SCANNER-UA": {"category": "scanner", "severity": "medium",
        "explanation": "The User-Agent belongs to an automated SQL injection tool such as sqlmap."},
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def categorize(result: Inspection, path: str) -> str | None:
    """Primary attack category of a flagged request (None for normal traffic)."""
    if result.verdict == "normal" or not result.matches:
        return None
    if path.rstrip("/") == "/api/login":
        return "auth_bypass"
    if any(m.decoded for m in result.matches):
        return "encoded"
    best = max(result.matches, key=lambda m: RULES_BY_ID[m.rule_id].weight)
    return RULE_INFO.get(best.rule_id, {}).get("category", "basic")


def verdict_reason(result: Inspection) -> str:
    if result.verdict == "blocked":
        return (f"Score {result.score} reached the block threshold of {BLOCK_SCORE}: "
                f"the request is rejected before any handler or query runs.")
    if result.verdict == "suspicious":
        return (f"Score {result.score} is between the suspicious threshold ({SUSPICIOUS_SCORE}) and the "
                f"block threshold ({BLOCK_SCORE}): the request is served, flagged and counted toward "
                f"repeat-attack detection.")
    return f"Score {result.score} is below the suspicious threshold of {SUSPICIOUS_SCORE}."


def explain(result: Inspection) -> list[dict]:
    """One entry per matched rule with its contribution to the score."""
    out = []
    for m in result.matches:
        rule = RULES_BY_ID[m.rule_id]
        info = RULE_INFO.get(rule.id, {})
        out.append({
            "rule_id": rule.id,
            "rule": rule.description,
            "weight": rule.weight,
            "category": info.get("category"),
            "category_label": CATEGORY_LABELS.get(info.get("category", ""), ""),
            "severity": info.get("severity"),
            "explanation": info.get("explanation", ""),
            "field": m.field,
            "snippet": m.snippet,
            "decoded": m.decoded,
        })
    return out


def analyse(fields: list[tuple[str, str]], path: str,
            disabled: frozenset[str] | set[str] = frozenset()) -> dict:
    """Run the real detector with per-stage timings, for the simulation lab."""
    import time

    t0 = time.perf_counter()
    normalised = [(name, normalise(raw)) for name, raw in fields if raw]
    t1 = time.perf_counter()
    result = inspect_fields(fields, disabled)
    t2 = time.perf_counter()
    category = categorize(result, path)
    t3 = time.perf_counter()
    return {
        "result": result,
        "category": category,
        "normalised": normalised,
        "timings_us": {
            "normalisation": int((t1 - t0) * 1e6),
            "detection": int((t2 - t1) * 1e6),
            "scoring": int((t3 - t2) * 1e6),
        },
    }
