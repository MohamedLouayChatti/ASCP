
from __future__ import annotations

import logging
from typing import List

import httpx
import numpy as np

logger = logging.getLogger(__name__)

# The model you already have downloaded
_DEFAULT_MODEL = "hf.co/CompendiumLabs/bge-base-en-v1.5-gguf:latest"
_OLLAMA_URL = "http://localhost:11434"


def get_embedding(
    text: str,
    model: str = _DEFAULT_MODEL,
    timeout: float = 10.0,
) -> List[float] | None:
    """
    Get embedding vector from Ollama BGE model.
    Returns None on failure so caller can decide fallback behavior.
    """
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(
                f"{_OLLAMA_URL}/api/embeddings",
                json={"model": model, "prompt": text},
            )
            response.raise_for_status()
            return response.json()["embedding"]
    except Exception as exc:
        logger.warning("BGE embedding failed for text='%s...': %s", text[:50], exc)
        return None


def cosine_similarity(a: List[float], b: List[float]) -> float:
    """Cosine similarity between two embedding vectors."""
    va = np.array(a, dtype=np.float32)
    vb = np.array(b, dtype=np.float32)
    norm_a = np.linalg.norm(va)
    norm_b = np.linalg.norm(vb)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(va, vb) / (norm_a * norm_b))


def best_semantic_score(
    claim: str,
    doc_sentences: List[str],
    model: str = _DEFAULT_MODEL,
    timeout: float = 10.0,
) -> tuple[float, str]:
    """
    Compare claim embedding against each sentence embedding.
    Returns (best_score, best_matching_sentence).

    This is the core semantic support check:
    - Embeds the claim once
    - Embeds each sentence in the document
    - Returns the highest cosine similarity found
    """
    claim_vec = get_embedding(claim, model=model, timeout=timeout)
    if claim_vec is None:
        return 0.0, ""

    best_score = 0.0
    best_sentence = ""

    for sent in doc_sentences:
        sent = sent.strip()
        if not sent:
            continue
        sent_vec = get_embedding(sent, model=model, timeout=timeout)
        if sent_vec is None:
            continue
        score = cosine_similarity(claim_vec, sent_vec)
        if score > best_score:
            best_score = score
            best_sentence = sent

    return round(best_score, 4), best_sentence