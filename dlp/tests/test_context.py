"""Tests for contextual window analysis (dlp/context.py)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlp.config import DLPConfig
from dlp.context import ContextAnalyzer
from dlp.models import DLPMatch, ScanSurface, DLPAction


def _match(value: str, start: int, action: DLPAction = DLPAction.REDACT) -> DLPMatch:
    return DLPMatch(
        pattern_name="email", category="pii", action=action,
        value=value, spans=[(start, start + len(value))],
        surface=ScanSurface.OUTPUT,
    )


def _make_analyzer(on_negation: str = "downgrade", window: int = 50) -> ContextAnalyzer:
    cfg = DLPConfig.defaults()
    cfg.enable_context_analysis = True
    cfg.context_window = window
    cfg.context_trigger_words = ["my", "real", "secret"]
    cfg.context_negation_words = ["example", "test", "fake", "documentation"]
    cfg.context_on_negation = on_negation
    return ContextAnalyzer(cfg)


class TestContextAnalyzer(unittest.TestCase):
    def test_clean_text_no_context_signal_kept(self):
        analyzer = _make_analyzer()
        text = "Contact us at user@company.com for support."
        start = text.index("user@company.com")
        m = _match("user@company.com", start)
        result = analyzer.filter([m], text)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].action, DLPAction.REDACT)

    def test_negation_only_downgraded(self):
        analyzer = _make_analyzer(on_negation="downgrade")
        text = "For example: user@company.com is how emails look."
        start = text.index("user@company.com")
        m = _match("user@company.com", start)
        result = analyzer.filter([m], text)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].action, DLPAction.ALLOW, "Negation-only → downgrade to ALLOW")

    def test_negation_only_suppressed(self):
        analyzer = _make_analyzer(on_negation="suppress")
        text = "For example: user@company.com is how emails look."
        start = text.index("user@company.com")
        m = _match("user@company.com", start)
        result = analyzer.filter([m], text)
        self.assertEqual(result, [], "Negation-only + suppress → dropped")

    def test_trigger_only_kept_at_original_action(self):
        analyzer = _make_analyzer()
        text = "My email is user@company.com please use it."
        start = text.index("user@company.com")
        m = _match("user@company.com", start)
        result = analyzer.filter([m], text)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].action, DLPAction.REDACT, "Trigger → keep at original action")

    def test_trigger_and_negation_trigger_wins(self):
        """When both trigger and negation words are present, trigger wins."""
        analyzer = _make_analyzer()
        text = "My real example email john@corp.com is in use"
        start = text.index("john@corp.com")
        m = _match("john@corp.com", start)
        result = analyzer.filter([m], text)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].action, DLPAction.REDACT, "Trigger wins over negation")

    def test_multiple_matches_independently_evaluated(self):
        analyzer = _make_analyzer()
        # Ensure the two emails are more than 50 chars apart so the
        # trigger word 'real' from the first match's context cannot
        # bleed into the 50-char context window of the second match.
        padding = "z" * 60  # > context_window=50
        text = f"My real contact real@corp.com {padding} For example: fake@corp.com done"
        start1 = text.index("real@corp.com")
        start2 = text.index("fake@corp.com")
        m1 = _match("real@corp.com", start1)
        m2 = _match("fake@corp.com", start2)
        result = analyzer.filter([m1, m2], text)
        # real@corp.com: trigger 'real' in pre-window → kept at REDACT
        # fake@corp.com: only negation 'example'/'fake' in window (trigger is >50 chars away)
        actions = {r.value: r.action for r in result}
        self.assertEqual(actions["real@corp.com"], DLPAction.REDACT)
        self.assertEqual(actions["fake@corp.com"], DLPAction.ALLOW)

    def test_empty_match_list(self):
        analyzer = _make_analyzer()
        result = analyzer.filter([], "any text")
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
