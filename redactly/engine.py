"""The redaction engine — turns raw text into tokenized text.

:class:`Redactor` is the provider-agnostic core. Per-provider adapters locate
*where the text lives* in a request body and call :meth:`Redactor.redact_text`
on each text field; the engine does the actual work:

1. Gather spans from the built-in detectors **and** the user rules.
2. Drop spans that fall on the allowlist (known-safe matches).
3. Resolve overlaps (prefer the most-specific / earliest-listed detector).
4. Mint a stable token for each surviving span via the vault.
5. Splice the tokens in **right-to-left** so earlier offsets stay valid as
   later (higher-offset) spans are replaced first.

Determinism is mandatory: the same input yields the same output (the vault
guarantees same-secret → same-token), so redacted bytes are stable across turns
and the provider's prompt cache still hits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .config import Allowlist, Config, UserRule
from .detectors import BUILTINS, Detector, Span, detect
from .vault import Vault


@dataclass(frozen=True)
class _RankedSpan:
    """A detected :class:`Span` tagged with its resolution priority.

    ``priority`` is the rank of the detector/rule that produced the span: the
    SMALLER the number, the MORE specific (higher confidence) the producer.
    User rules sort ahead of every built-in detector (they are precise by
    construction — the user explicitly declared the value sensitive), then the
    built-in detectors follow in their listed, most-specific-first order.

    The overlap resolver uses ``priority`` first, then leftmost-longest, so the
    winner between two overlapping spans is deterministic.
    """

    span: Span
    priority: int


class Redactor:
    """Gathers spans, resolves overlaps, mints tokens, and splices text.

    Args:
        vault: The session vault used to mint stable tokens (and later to
            un-mask the reply).
        detectors: Built-in detectors to run (default :data:`BUILTINS`).
        user_rules: User-declared rules; compiled into detectors and run
            alongside the built-ins (precise, opt-in).
        allowlist: Known-safe values to drop before tokenizing.
    """

    def __init__(
        self,
        vault: Vault,
        detectors: tuple[Detector, ...] = BUILTINS,
        user_rules: tuple[UserRule, ...] = (),
        allowlist: Allowlist | None = None,
    ) -> None:
        self.vault = vault
        self.detectors = detectors
        self.user_rules = user_rules
        self.allowlist = allowlist if allowlist is not None else Allowlist()

        # Compile user rules into detectors once, up front. A user rule is a
        # name/pattern/token_prefix with no validator, so it maps cleanly onto a
        # Detector (validate defaults to None). Compiling here means a broken
        # user pattern surfaces at construction (fail-closed wiring) rather than
        # on the first request. `detect()` re-compiles the string pattern, but
        # building the Detector tuple eagerly is what guarantees the rule shape
        # is valid before any traffic flows.
        self._rule_detectors: tuple[Detector, ...] = tuple(
            Detector(
                name=rule.name,
                pattern=rule.pattern,
                token_prefix=rule.token_prefix,
                validate=None,
            )
            for rule in self.user_rules
        )

        # Pre-compile allowlist patterns once. A bad allowlist regex is a config
        # error we want to raise eagerly, not swallow per-request.
        self._allow_patterns: tuple[re.Pattern[str], ...] = tuple(
            re.compile(p) for p in self.allowlist.patterns
        )
        self._allow_literals: frozenset[str] = self.allowlist.literals

    def redact_text(self, s: str) -> str:
        """Return ``s`` with every detected secret replaced by a stable token.

        Pipeline: detect (built-ins + user rules) → drop allowlisted → resolve
        overlaps → mint tokens via ``self.vault.token_for`` → splice
        right-to-left. Pure and deterministic: no secret value appears in the
        returned string, and the same input always yields the same output.

        On empty / non-secret-bearing input this returns the input unchanged.
        It MUST NOT swallow detector/vault errors — a raise here is what makes
        the proxy fail closed (the caller blocks rather than forwarding raw
        text).
        """
        # Cheap short-circuit: empty / whitespace-only strings carry no secret.
        # Note we deliberately do NOT broaden this to "no interesting chars" —
        # missing a secret is the failure mode the policy biases against
        # (high-recall), so anything non-trivial goes through the full scan.
        if not s:
            return s

        ranked = self._gather(s)
        if not ranked:
            return s

        ranked = self._drop_allowlisted_ranked(ranked)
        if not ranked:
            return s

        spans = self._resolve_overlaps_ranked(ranked)
        if not spans:
            return s

        return self._splice(s, spans)

    # ------------------------------------------------------------------
    # Gather
    # ------------------------------------------------------------------
    def _gather(self, s: str) -> list[_RankedSpan]:
        """Collect detector + user-rule spans, each tagged with its priority.

        User rules outrank every built-in detector (they are explicit user
        intent), so they are gathered first with the lowest priority numbers;
        built-in detectors follow in their listed most-specific-first order.

        Errors from ``detect`` (e.g. a bad regex) propagate — fail-closed.
        """
        ranked: list[_RankedSpan] = []
        priority = 0

        # User rules first — highest priority (smallest numbers).
        for rd in self._rule_detectors:
            for span in detect(s, (rd,)):
                ranked.append(_RankedSpan(span=span, priority=priority))
            priority += 1

        # Built-in detectors next, in their declared (most-specific-first) order.
        for det in self.detectors:
            for span in detect(s, (det,)):
                ranked.append(_RankedSpan(span=span, priority=priority))
            priority += 1

        return ranked

    # ------------------------------------------------------------------
    # Allowlist
    # ------------------------------------------------------------------
    def _drop_allowlisted(self, spans: list[Span]) -> list[Span]:
        """Remove spans whose matched text is on the allowlist.

        Allowlisting un-redacts a known-safe value (``localhost``,
        ``example.com``, a common port) that happened to match a detector. It
        never adds redaction. ``literals`` are exact-match against the span's
        matched text; ``patterns`` are regexes that must fully match the text.
        """
        return [span for span in spans if not self._is_allowlisted(span.text)]

    def _drop_allowlisted_ranked(self, ranked: list[_RankedSpan]) -> list[_RankedSpan]:
        """Allowlist filter that preserves each span's priority tag."""
        return [r for r in ranked if not self._is_allowlisted(r.span.text)]

    def _is_allowlisted(self, text: str) -> bool:
        """Return ``True`` if ``text`` is a known-safe (allowlisted) value."""
        if text in self._allow_literals:
            return True
        for pat in self._allow_patterns:
            # fullmatch: an allowlist pattern un-redacts a value only when it
            # describes the WHOLE matched secret, never a substring of it.
            if pat.fullmatch(text) is not None:
                return True
        return False

    # ------------------------------------------------------------------
    # Overlap resolution
    # ------------------------------------------------------------------
    def _resolve_overlaps(self, spans: list[Span]) -> list[Span]:
        """Drop overlapping spans, keeping the most-specific (earliest) match.

        Detectors are ordered most-specific-first, so when two spans cover the
        same bytes the one whose detector was listed earlier wins. Returns a
        non-overlapping list sorted by ``start``.

        This convenience overload accepts bare spans (no external priority tag)
        and assigns priority by their position in the list — callers that need
        cross-detector priority should use the internal ranked path, which
        :meth:`redact_text` does.
        """
        ranked = [_RankedSpan(span=span, priority=i) for i, span in enumerate(spans)]
        return self._resolve_overlaps_ranked(ranked)

    def _resolve_overlaps_ranked(self, ranked: list[_RankedSpan]) -> list[Span]:
        """Resolve overlaps over priority-tagged spans → non-overlapping spans.

        Selection order (a greedy interval pick):

        1. Highest priority wins (smallest ``priority`` — most specific / a user
           rule beats a built-in beats a broader built-in).
        2. Tie → leftmost (smallest ``start``).
        3. Tie → longest (largest ``end`` — leftmost-longest).
        4. Tie → most-specific producer again is already covered by (1); final
           tiebreak is the matched text so the order is total and deterministic.

        Zero-width spans (``start == end``) are discarded — there is nothing to
        mask and they would wedge the splice. The result is sorted by ``start``.
        """
        # Total, deterministic ordering. We pick winners greedily off the front
        # of this list and discard anything that overlaps an already-picked span.
        ordered = sorted(
            (r for r in ranked if r.span.end > r.span.start),
            key=lambda r: (
                r.priority,        # most-specific / user-rule first
                r.span.start,      # leftmost
                -r.span.end,       # longest (leftmost-longest)
                r.span.text,       # final deterministic tiebreak
            ),
        )

        chosen: list[Span] = []
        for r in ordered:
            span = r.span
            if any(self._overlaps(span, kept) for kept in chosen):
                continue
            chosen.append(span)

        chosen.sort(key=lambda sp: sp.start)
        return chosen

    @staticmethod
    def _overlaps(a: Span, b: Span) -> bool:
        """Return ``True`` if half-open ``[start, end)`` spans ``a`` and ``b`` overlap.

        Adjacency (``a.end == b.start``) does NOT count as overlap — two
        back-to-back secrets are both masked.
        """
        return a.start < b.end and b.start < a.end

    # ------------------------------------------------------------------
    # Splice
    # ------------------------------------------------------------------
    def _splice(self, s: str, spans: list[Span]) -> str:
        """Replace each span with its minted token, splicing right-to-left.

        Two passes, with a deliberate order to each:

        1. **Mint left-to-right.** Tokens are minted in *reading order* so the
           per-prefix counter ``N`` runs with the text (``«EMAIL_1»`` precedes
           ``«EMAIL_2»`` on the page). The vault dedups, so this only affects the
           numbering of first-seen secrets, never correctness — but it keeps the
           "Count" signal intuitive for the model and the bytes stable.
        2. **Splice right-to-left.** Applying replacements from the highest
           offset down keeps every not-yet-applied span's ``[start, end)`` valid
           against the original string while earlier replacements change its
           length.

        ``spans`` must be non-overlapping. ``vault.token_for`` may raise — it is
        allowed to propagate (fail-closed).
        """
        by_start = sorted(spans, key=lambda sp: sp.start)

        # Pass 1: mint in reading order (vault dedups same secret → same token).
        tokens: dict[int, str] = {
            span.start: self.vault.token_for(span.text, span.prefix)
            for span in by_start
        }

        # Pass 2: splice from the right so earlier offsets stay valid.
        out = s
        for span in reversed(by_start):
            out = out[: span.start] + tokens[span.start] + out[span.end :]
        return out


def build_redactor(config: Config, vault: Vault) -> Redactor:
    """Construct a :class:`Redactor` for a request/session from resolved config.

    This is the wiring helper the proxy uses when it builds the per-request
    vault + redactor: it pulls the user rules and allowlist off the resolved
    :class:`~redactly.config.Config` (already loaded from env + the rules file
    via :func:`redactly.config.load`) and hands them to the engine, alongside
    the built-in detectors.

    Keeping this here — rather than re-parsing a rules file — means the engine
    has exactly one way to be built from config and the file-format concern
    stays in ``redactly.config`` (the single source of truth for rule loading).
    A malformed rules file has already failed closed at ``config.load`` time, so
    by the time we get here ``config.user_rules`` / ``config.allowlist`` are
    valid; any bad *pattern* still surfaces eagerly here at compile time.
    """
    return Redactor(
        vault=vault,
        detectors=BUILTINS,
        user_rules=config.user_rules,
        allowlist=config.allowlist,
    )
