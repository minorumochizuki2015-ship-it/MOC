"""
Application factory for ORCH-Next
- Fail-fast verification of required templates and static assets
- URL Map dump on startup for audit/observability
"""

import logging
import os
from typing import List

from flask import Flask

logger = logging.getLogger(__name__)


def _verify_assets(app: Flask) -> None:
    """Fail-fast verification for essential templates and static assets.

    Raises RuntimeError when a required asset is missing.
    """
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    templates_dir = app.template_folder or os.path.join(project_root, "templates")
    static_dir = app.static_folder or os.path.join(project_root, "static")

    required_templates: List[str] = [
        os.path.join(templates_dir, "dashboard.html"),
        os.path.join(templates_dir, "agents.html"),
    ]

    missing_templates = [p for p in required_templates if not os.path.exists(p)]
    if missing_templates:
        for mt in missing_templates:
            logger.error(f"Missing template detected (fail-fast): {mt}")
        raise RuntimeError("Required templates are missing. See logs for details.")

    # Static directory is optional in this repository, but if present ensure it is readable
    if os.path.exists(static_dir) and not os.path.isdir(static_dir):
        raise RuntimeError(f"Static path exists but is not a directory: {static_dir}")

    logger.info(
        {
            "event": "asset_verification_passed",
            "templates_dir": templates_dir,
            "static_dir": static_dir,
            "verified_templates": required_templates,
        }
    )


def _dump_url_map(app: Flask) -> None:
    """Log URL map for audit purposes."""
    try:
        rules = []
        for rule in app.url_map.iter_rules():
            rules.append(
                {
                    "endpoint": rule.endpoint,
                    "methods": sorted([m for m in rule.methods if m not in {"HEAD", "OPTIONS"}]),
                    "rule": str(rule),
                }
            )
        logger.info({"event": "url_map_dump", "rules": rules})
    except Exception as e:
        logger.warning({"event": "url_map_dump_failed", "error": str(e)})


def create_app() -> Flask:
    """Create and configure the Flask application.

    This factory registers UI/API/SSE blueprints, performs asset verification,
    and dumps the URL map to logs for audit.
    """
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    app = Flask(
        __name__,
        template_folder=os.path.join(project_root, "templates"),
        static_folder=os.path.join(project_root, "static"),
    )

    # Register blueprints if available
    try:
        from src.blueprints.api_routes import api_bp
        from src.blueprints.sse_routes import sse_bp
        from src.blueprints.ui_routes import ui_bp

        app.register_blueprint(ui_bp)
        app.register_blueprint(api_bp, url_prefix="/api")
        app.register_blueprint(sse_bp, url_prefix="/sse")
        logger.info({"event": "blueprints_registered", "blueprints": ["ui", "api", "sse"]})
    except Exception as e:
        logger.error({"event": "blueprint_registration_failed", "error": str(e)})
        # Do not swallow; fail fast to avoid partially running app
        raise

    # Fail-fast: verify required assets before serving
    _verify_assets(app)

    # Log URL map for audit
    _dump_url_map(app)

    return app
