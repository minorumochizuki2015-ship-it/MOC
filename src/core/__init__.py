"""Core kernel package exposing the minimal API.

This package provides a stable interface for text generation and utility
endpoints used across the project. It is intentionally lightweight and avoids
external dependencies by default, while remaining easy to delegate to a
provider (e.g., teae) in future iterations.
"""

from .kernel import _model_id, generate, generate_chat, healthcheck, read_paths

__all__ = [
    "generate",
    "generate_chat",
    "read_paths",
    "healthcheck",
    "_model_id",
]
