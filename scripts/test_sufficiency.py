from pathlib import Path
import sys

# Ensure the project root is importable when running as a script.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from grounding.sufficiency import check_sufficiency


# Test 1 - misleading keyword match (dangerous case)
result = check_sufficiency(
    query="What caused the 2008 financial crisis?",
    documents=[
        "The 2008 financial crisis was a major global event affecting millions.",
        "Subprime mortgage lending and lack of regulation caused the 2008 crisis.",
    ],
)
print(f"Test 1 (complex query): {result.context_sufficiency}")
print(f"  query_type={result.query_type} | relevance={result.retrieval_relevance}")
print(f"  recommendation={result.recommendation}\n")

# Test 2 - numeric query without numbers in docs
result = check_sufficiency(
    query="How many visitors does the Eiffel Tower attract per year?",
    documents=[
        "The Eiffel Tower is a famous landmark located in Paris France.",
    ],
)
print(f"Test 2 (numeric, no numbers in doc): {result.context_sufficiency}")
print(f"  recommendation={result.recommendation}\n")

# Test 3 - genuinely sufficient
result = check_sufficiency(
    query="How many visitors does the Eiffel Tower attract per year?",
    documents=[
        "The Eiffel Tower attracts approximately 7 million visitors per year.",
    ],
)
print(f"Test 3 (numeric, doc has answer): {result.context_sufficiency}")
print(f"  recommendation={result.recommendation}\n")

# Test 4 - no documents at all
result = check_sufficiency(
    query="What is data leakage?",
    documents=[],
)
print(f"Test 4 (no docs): {result.context_sufficiency}")
print(f"  recommendation={result.recommendation}")
