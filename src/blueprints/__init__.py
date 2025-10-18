# Blueprint modules for ORCH Dashboard
# Modular route organization for maintainability and testing

from .admin_routes import admin_bp
from .api_routes import api_bp
from .sse_routes import sse_bp
from .ui_routes import ui_bp

__all__ = ["ui_bp", "api_bp", "sse_bp", "admin_bp"]
