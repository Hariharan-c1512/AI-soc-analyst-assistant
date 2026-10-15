"""RAG engine — retrieves similar past incidents to enrich LLM prompts.

Uses sentence-transformers when available for lightweight local semantic search;
if it is not installed or cannot load, it falls back to a TF-IDF similarity
index so the feature still works with the minimal dependency set.
"""
import logging
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

try:
    from sentence_transformers import SentenceTransformer
    HAS_HEAVY = True
except ImportError:  # pragma: no cover
    SentenceTransformer = None
    HAS_HEAVY = False

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .config import settings


class RAGEngine:
    def __init__(self):
        self.heavy = HAS_HEAVY and SentenceTransformer is not None
        self._documents: list[dict] = []
        self._vectorizer: Optional[TfidfVectorizer] = None
        self._matrix = None
        self._embeddings: list[np.ndarray] = []
        self._encoder = None
        if self.heavy:
            try:
                self._encoder = SentenceTransformer(settings.EMBEDDING_MODEL)
            except Exception as e:  # pragma: no cover
                logger.warning("Embedding model load failed (%s); using TF-IDF", e)
                self.heavy = False

    def index_alert(self, alert: dict):
        """Add an alert to the retrieval index."""
        text = f"{alert.get('sigma_title', '')} {alert.get('description', '')} {alert.get('raw_log', '')}"
        record = {
            "alert_ref": alert.get("alert_ref"),
            "description": alert.get("description"),
            "similarity": 0.0,
            "text": text[:2000],
        }
        self._documents.append(record)

        if self.heavy and self._encoder is not None:
            try:
                embedding = self._encoder.encode(
                    record["text"],
                    convert_to_numpy=True,
                    normalize_embeddings=True,
                )
                self._embeddings.append(np.asarray(embedding, dtype=np.float32))
            except Exception as e:  # pragma: no cover
                logger.warning("Embedding generation failed for alert %s (%s); falling back", alert.get("alert_ref"), e)
                self._embeddings.append(np.zeros(384, dtype=np.float32))

    def _build_matrix(self):
        self._vectorizer = TfidfVectorizer(stop_words="english")
        self._matrix = self._vectorizer.fit_transform([d["text"] for d in self._documents])

    def retrieve(self, query: str, top_k: Optional[int] = None) -> list[dict]:
        """Return top-k similar documents."""
        k = top_k or settings.RAG_TOP_K
        if not self._documents:
            return []

        if self.heavy and self._encoder is not None and len(self._embeddings) == len(self._documents):
            try:
                query_vector = np.asarray(
                    self._encoder.encode(query, convert_to_numpy=True, normalize_embeddings=True),
                    dtype=np.float32,
                )
                embedding_matrix = np.vstack(self._embeddings)
                sims = cosine_similarity(query_vector.reshape(1, -1), embedding_matrix).flatten()
            except Exception as e:  # pragma: no cover
                logger.warning("Embedding search failed (%s); using TF-IDF fallback", e)
                sims = None
            if sims is not None:
                order = sims.argsort()[::-1]
                results = []
                for idx in order[:k]:
                    if sims[idx] <= 0:
                        continue
                    d = dict(self._documents[idx])
                    d["similarity"] = round(float(sims[idx]), 3)
                    results.append(d)
                return results

        if self._matrix is None:
            self._build_matrix()
        qvec = self._vectorizer.transform([query])
        sims = cosine_similarity(qvec, self._matrix).flatten()
        order = sims.argsort()[::-1]
        results = []
        for idx in order[:k]:
            if sims[idx] <= 0:
                continue
            d = dict(self._documents[idx])
            d["similarity"] = round(float(sims[idx]), 3)
            results.append(d)
        return results


_rag: Optional[RAGEngine] = None


def get_rag() -> RAGEngine:
    global _rag
    if _rag is None:
        _rag = RAGEngine()
    return _rag
