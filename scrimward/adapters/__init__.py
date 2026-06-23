"""Per-provider body adapters.

The engine is provider-agnostic; an :class:`~scrimward.adapters.base.Adapter`
knows only *where the text lives* in one provider's request body and streamed
response. The proxy holds an ordered list of adapters and picks the first whose
:meth:`Adapter.matches` returns ``True``. If **none** match, the proxy fails
closed (5xx, forward nothing) — there is no default passthrough adapter.

Built-in adapters (registration order = match priority):

- :class:`~scrimward.adapters.anthropic.AnthropicAdapter` — Anthropic Messages
  (``/v1/messages``).
- :class:`~scrimward.adapters.openai_chat.OpenAIChatAdapter` — OpenAI Chat
  Completions (``/v1/chat/completions``).
"""

from __future__ import annotations

from .anthropic import AnthropicAdapter
from .base import Adapter
from .openai_chat import OpenAIChatAdapter
from .openai_responses import OpenAIResponsesAdapter

# Ordered registry the proxy iterates to pick an adapter (first match wins).
# Paths are disjoint (/v1/messages, /v1/chat/completions, /v1/responses), so
# order is not load-bearing here.
ADAPTERS: tuple[Adapter, ...] = (
    AnthropicAdapter(),
    OpenAIChatAdapter(),
    OpenAIResponsesAdapter(),
)

__all__ = [
    "Adapter",
    "AnthropicAdapter",
    "OpenAIChatAdapter",
    "OpenAIResponsesAdapter",
    "ADAPTERS",
]
