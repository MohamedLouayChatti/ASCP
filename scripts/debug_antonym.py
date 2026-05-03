# scripts/debug_antonym.py

import sys
from pathlib import Path

# Ensure the project root is importable when running as a script.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import re
from grounding.consistency_checker import _ANTONYM_PAIRS
from grounding.text_utils import topic_overlap

claim_text = "External access is allowed for all verified users."
doc_text   = "The security policy strictly forbids external access."

lower_claim = claim_text.lower()
lower_doc   = doc_text.lower()

print("=== Raw text ===")
print(f"Claim : {lower_claim}")
print(f"Doc   : {lower_doc}")
print()

print("=== Checking every pair with prefix stems ===")
for word_a, word_b in _ANTONYM_PAIRS:
    stem_a = word_a[:max(4, len(word_a) - 2)]
    stem_b = word_b[:max(4, len(word_b) - 2)]

    a_has_a = bool(re.search(rf"\b{stem_a}\w*\b", lower_claim))
    b_has_b = bool(re.search(rf"\b{stem_b}\w*\b", lower_doc))
    a_has_b = bool(re.search(rf"\b{stem_b}\w*\b", lower_claim))
    b_has_a = bool(re.search(rf"\b{stem_a}\w*\b", lower_doc))

    fires = (a_has_a and b_has_b) or (a_has_b and b_has_a)

    # Print every pair that has at least one hit anywhere
    if any([a_has_a, b_has_b, a_has_b, b_has_a]):
        print(
            f"  ({word_a:12} / {word_b:12}) "
            f"stem=({stem_a}/{stem_b}) | "
            f"claim=({a_has_a}/{a_has_b}) "
            f"doc=({b_has_a}/{b_has_b}) "
            f"→ FIRES={fires}"
        )

print()
print("=== Manual stem check for 'allowed' vs 'forbidden' ===")
# word_a = "allowed", word_b = "forbidden"
word_a, word_b = "allowed", "forbidden"
stem_a = word_a[:max(4, len(word_a) - 2)]
stem_b = word_b[:max(4, len(word_b) - 2)]
print(f"stem_a = '{stem_a}'  (from '{word_a}')")
print(f"stem_b = '{stem_b}'  (from '{word_b}')")
print(f"regex for stem_a in claim : r'\\b{stem_a}\\w*\\b'")
print(f"regex for stem_b in doc   : r'\\b{stem_b}\\w*\\b'")
print()

a_has_a = bool(re.search(rf"\b{stem_a}\w*\b", lower_claim))
b_has_b = bool(re.search(rf"\b{stem_b}\w*\b", lower_doc))
print(f"'{stem_a}\\w*' found in claim : {a_has_a}")
print(f"'{stem_b}\\w*' found in doc   : {b_has_b}")
print(f"Should fire                  : {a_has_a and b_has_b}")
print()

print("=== Manual check for 'forbid' in doc ===")
for pattern in ["forbid", "forbids", "forbidden", "forb"]:
    found = bool(re.search(rf"\b{pattern}\w*\b", lower_doc))
    print(f"  pattern '\\b{pattern}\\w*\\b' in doc: {found}")