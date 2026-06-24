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

import hashlib
import re
import unicodedata
from dataclasses import dataclass

from .config import Allowlist, Config, UserRule
from .detectors import BUILTINS, Detector, Span, detect
from .vault import Vault


# Dict keys whose ``data`` child is raw binary base64 (image/file), not text —
# the recursive backstop must not run text redaction over them.
_IMAGE_PARENTS = frozenset({"source", "inlinedata", "inline_data"})


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
        redact_images: bool = False,
        redact_pdf: bool = False,
        detect_entropy: bool = False,
    ) -> None:
        self.vault = vault
        # The shapeless high-entropy catch-all is OPT-IN (REDACT_ENTROPY): it has
        # high recall but masks git SHAs / content hashes / UUIDs that pepper
        # coding prompts, so it's filtered out unless explicitly enabled.
        self.detect_entropy = detect_entropy
        self.detectors = (
            detectors
            if detect_entropy
            else tuple(d for d in detectors if d.name != "high_entropy_string")
        )
        self.user_rules = user_rules
        self.allowlist = allowlist if allowlist is not None else Allowlist()
        # Per-request image policy carried alongside the text redactor: when True
        # (and Apple Vision is available) adapters redact images in place instead
        # of failing closed. Default False — images are refused (fail-closed).
        self.redact_images = redact_images
        # PDF redaction is a separate opt-in: it rasterizes each page (dropping
        # the searchable text layer), a heavier transform than image redaction.
        self.redact_pdf = redact_pdf

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
        self._allow_hashes: frozenset[str] = self.allowlist.hashes

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

        # Normalize a COPY for DETECTION only — NFKC folds full-width /
        # compatibility homoglyphs and the Cf-strip removes zero-width spaces / BOM
        # / soft hyphens an attacker splices into a secret to dodge every regex
        # ("AKIA​…"). But we must NOT corrupt secret-free content: when nothing is
        # masked we forward the ORIGINAL bytes verbatim. Only when a secret IS
        # found do we splice on (and emit) the normalized string — and that string
        # is being heavily rewritten anyway, with the secret region masked.
        norm = self._normalize(s)

        ranked = self._gather(norm)
        if not ranked:
            return s

        ranked = self._drop_allowlisted_ranked(ranked)
        if not ranked:
            return s

        spans = self._resolve_overlaps_ranked(norm, ranked)
        if not spans:
            return s

        return self._splice(norm, spans)

    def redact_object(self, obj: object) -> object:
        """Deny-by-default recursive backstop: redact EVERY string leaf in a
        JSON-decoded object IN PLACE, except opaque/binary fields.

        Adapters can only hand-enumerate the text fields they know about; a field
        a provider adds tomorrow (a new tool-call arg, a description, metadata)
        would otherwise be re-serialized verbatim and leak. This sweep masks any
        un-enumerated text so the adapter layer is fail-CLOSED by construction.
        Opaque fields are skipped (they are handled separately or must not be
        mutated): inline ``data:`` URIs, raw image base64 (``data`` under
        ``source``/``inlineData``), and ``encrypted_content`` server blobs.
        """
        return self._redact_node(obj, key=None, parent_key=None)

    def _is_opaque(self, value: str, key: str | None, parent_key: str | None) -> bool:
        if value[:5].lower() == "data:":  # any inline image/pdf/audio data URI
            return True
        if isinstance(key, str):
            kl = key.lower()
            if kl == "encrypted_content":
                return True
            if kl == "data" and parent_key in _IMAGE_PARENTS:
                return True
        return False

    def _redact_node(self, node: object, key: str | None, parent_key: str | None) -> object:
        if isinstance(node, str):
            return node if self._is_opaque(node, key, parent_key) else self.redact_text(node)
        if isinstance(node, dict):
            node_key = key.lower() if isinstance(key, str) else None
            for k in list(node.keys()):
                node[k] = self._redact_node(node[k], k if isinstance(k, str) else None, node_key)
            return node
        if isinstance(node, list):
            for i in range(len(node)):
                node[i] = self._redact_node(node[i], None, parent_key)
            return node
        return node  # int / float / bool / None — nothing to redact

    @staticmethod
    def _normalize(s: str) -> str:
        """NFKC-fold then strip Unicode format (Cf) chars, to defeat evasion.

        NFKC collapses full-width / compatibility homoglyphs to their canonical
        ASCII form; the Cf strip removes zero-width spaces, BOM, soft hyphens and
        other invisible format characters NFKC leaves in place. Both run before
        detection so a secret obfuscated with either trick is still matched, and
        the normalized string is what gets forwarded (the model never relies on
        these characters). The common case (no Cf chars) skips the rebuild.
        """
        s = unicodedata.normalize("NFKC", s)
        if any(unicodedata.category(c) == "Cf" for c in s):
            s = "".join(c for c in s if unicodedata.category(c) != "Cf")
        return s

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
        if self._allow_hashes:
            # SHA-256 hex of the matched text — lets a reviewed FP be suppressed
            # without storing the raw value in config (ggshield-style).
            if hashlib.sha256(text.encode("utf-8")).hexdigest() in self._allow_hashes:
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
    def _resolve_overlaps(self, s: str, spans: list[Span]) -> list[Span]:
        """Convenience overload over bare spans (priority = list position)."""
        ranked = [_RankedSpan(span=span, priority=i) for i, span in enumerate(spans)]
        return self._resolve_overlaps_ranked(s, ranked)

    def _resolve_overlaps_ranked(self, s: str, ranked: list[_RankedSpan]) -> list[Span]:
        """Merge overlapping priority-tagged spans into non-overlapping UNION spans.

        Overlapping spans are coalesced into one masked region (the union) rather
        than keeping only the most-specific one and leaking the discarded span's
        flanking bytes. This is the load-bearing fix that lets the high-entropy
        catch-all safely overlap a vendor match: the whole run is masked, not
        just the vendor sub-span.

        Algorithm — a max-end sweep computing connected components (transitive
        overlap closure), order-independent:

        1. Drop zero-width spans (``start == end``) — nothing to mask; they would
           wedge the splice.
        2. Sort by geometry ``(start, end, text)``; clustering is purely geometric.
        3. Sweep: a span whose ``start`` is **strictly** less than the running
           cluster end joins it (strict ``<`` reproduces :meth:`_overlaps` —
           adjacency ``next.start == cur_end`` starts a NEW cluster, so two
           back-to-back secrets stay separate).
        4. Emit one ``Span`` per cluster covering ``[cstart, cend)`` whose
           ``text`` is the exact union substring ``s[cstart:cend]`` (so the vault
           mints/unmasks the right bytes), and whose ``name``/``prefix`` come from
           the **lowest-priority-number (most-specific)** contributor — never from
           the matched text — so identical inputs always coalesce to identical
           tokens (prompt-cache stability).
        """
        items = [r for r in ranked if r.span.end > r.span.start]
        if not items:
            return []
        items.sort(key=lambda r: (r.span.start, r.span.end, r.span.text))

        clusters: list[list[_RankedSpan]] = []
        current: list[_RankedSpan] = [items[0]]
        current_end = items[0].span.end
        for r in items[1:]:
            if r.span.start < current_end:  # overlap → same cluster
                current.append(r)
                current_end = max(current_end, r.span.end)
            else:  # disjoint or merely adjacent → new cluster
                clusters.append(current)
                current = [r]
                current_end = r.span.end
        clusters.append(current)

        out: list[Span] = []
        for members in clusters:
            cstart = members[0].span.start  # members are start-sorted
            cend = max(m.span.end for m in members)
            winner = min(
                members,
                key=lambda r: (r.priority, r.span.start, -r.span.end, r.span.text),
            )
            out.append(
                Span(
                    start=cstart,
                    end=cend,
                    name=winner.span.name,
                    prefix=winner.span.prefix,
                    text=s[cstart:cend],
                )
            )
        out.sort(key=lambda sp: sp.start)
        return out

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
    :class:`~scrimward.config.Config` (already loaded from env + the rules file
    via :func:`scrimward.config.load`) and hands them to the engine, alongside
    the built-in detectors.

    Keeping this here — rather than re-parsing a rules file — means the engine
    has exactly one way to be built from config and the file-format concern
    stays in ``scrimward.config`` (the single source of truth for rule loading).
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
