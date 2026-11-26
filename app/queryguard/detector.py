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


def _strip_inline_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)


def inspect_fields(fields: list[tuple[str, str]]) -> Inspection:
    """Score a request from (field name, raw value) pairs."""
    result = Inspection()
    matched_rules: set[str] = set()

    for name, raw in fields:
        if not raw:
            continue
        text = normalise(raw)
        if not text:
            continue
        variants = {text, _strip_inline_comments(text)}
        for rule in RULES:
            if rule.id in matched_rules:
                continue
            if rule.id == "SCANNER-UA" and name != "header:user-agent":
                continue
            if rule.id != "SCANNER-UA" and name == "header:user-agent":
                continue
            for variant in variants:
                if rule.pattern.search(variant):
                    matched_rules.add(rule.id)
                    result.matches.append(Match(rule.id, name, text[:200]))
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
