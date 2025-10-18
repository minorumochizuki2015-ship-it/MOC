"""
Compatibility shim for tests expecting `kernel` at repository root.
Delegate to src.core.kernel implementation.
"""

from src.core.kernel import _model_id, generate, generate_chat, healthcheck, read_paths

__all__ = [
    "generate",
    "generate_chat",
    "read_paths",
    "healthcheck",
    "_model_id",
]
