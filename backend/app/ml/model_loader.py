from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib


LOGGER = logging.getLogger(__name__)
DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "phishing_model.pkl"

_cached_model: Any | None = None
_load_attempted = False


def load_model(model_path: str | Path | None = None) -> Any | None:
    """
    Load the phishing model once and cache it for process reuse.
    """
    global _cached_model, _load_attempted

    if _cached_model is not None:
        return _cached_model

    if _load_attempted:
        return None

    _load_attempted = True
    resolved_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH

    try:
        if not resolved_path.exists():
            LOGGER.warning("Phishing model not found at %s", resolved_path)
            return None

        _cached_model = joblib.load(resolved_path)
        LOGGER.info("Loaded phishing model from %s", resolved_path)
        return _cached_model
    except Exception:
        LOGGER.exception("Failed to load phishing model from %s", resolved_path)
        return None


def get_model() -> Any | None:
    return load_model()
