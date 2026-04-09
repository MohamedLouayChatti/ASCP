"""
Context-aware false positive reduction for DLP matches.

The text surrounding a match dramatically changes its risk level:
  HIGH RISK : "My AWS key is AKIA..." → confirmed leak
  LOW RISK  : "The format of an AWS key is AKIA..." → documentation

ContextAnalyzer inspects a configurable character window around each match.
If negation words are present without any trigger words, the match is either:
  - "suppress" : dropped entirely (no audit trail — use when confident in word lists)
  - "downgrade": action set to ALLOW (kept in telemetry, not actioned)

Both modes are conservative: if a trigger word exists alongside a negation word,
the trigger wins and the match is kept at its original action.
"""

from dataclasses import replace
import re

from .models import DLPMatch, DLPAction
from .config import DLPConfig

EXAMPLE_KEYWORDS = [
    r"\bexample\b", r"\bdummy\b", r"\bsample\b", r"\bplaceholder\b",
    r"\bdocumentation\b", r"\btutorial\b", r"\bmock\b"
]

def contains_example_context(text: str) -> bool:
    """
    Check if the text implies an example/dummy context to downgrade confidence.
    """
    txt_lower = text.lower()
    for kw in EXAMPLE_KEYWORDS:
        if re.search(kw, txt_lower):
            return True
    return False

class ContextAnalyzer:
    """
    Adjusts or suppresses DLP matches based on their surrounding textual context.

    context_on_negation (configurable in YAML):
      "downgrade" (default) — set action=ALLOW; match is kept for telemetry
      "suppress"            — drop match entirely; reduces noise when word lists
                              are well-tuned for the deployment domain
    """

    def __init__(self, config: DLPConfig):
        self.config = config
        self._triggers = [w.lower() for w in config.context_trigger_words]
        self._negations = [w.lower() for w in config.context_negation_words]

    def _context_window(self, text: str, spans: list[tuple[int, int]]) -> str:
        """Extract combined pre/post context around all spans of a match."""
        w = self.config.context_window
        parts: list[str] = []
        for start, end in spans:
            pre = text[max(0, start - w):start]
            post = text[end:min(len(text), end + w)]
            parts.append(pre + " " + post)
        return " ".join(parts).lower()

    def filter(self, matches: list[DLPMatch], text: str) -> list[DLPMatch]:
        """
        Filter matches based on surrounding context signals.

        Only adjusts when ALL of:
          - at least one negation word is in the context window
          - NO trigger word is in the context window
        This is intentionally conservative: ambiguous cases always keep the match.
        """
        result: list[DLPMatch] = []
        for m in matches:
            ctx = self._context_window(text, m.spans)
            has_trigger = any(t in ctx for t in self._triggers)
            has_negation = any(n in ctx for n in self._negations)

            if has_negation and not has_trigger:
                if self.config.context_on_negation == "suppress":
                    continue  # drop — appropriate for well-tuned deployments
                else:
                    # downgrade (default): zero action, keep in telemetry
                    result.append(replace(m, action=DLPAction.ALLOW))
            else:
                result.append(m)

        return result
