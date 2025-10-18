"""
UI Routes Blueprint
Handles all user interface routes for the ORCH Dashboard
"""

import logging

from flask import Blueprint, render_template

ui_bp = Blueprint("ui", __name__)
logger = logging.getLogger(__name__)


@ui_bp.route("/")
@ui_bp.route("/dashboard")
def dashboard():
    """Main dashboard page"""
    logger.info("Serving main dashboard page")
    return render_template("dashboard.html", title="ORCH統合管理システム")


@ui_bp.route("/tasks")
def tasks_page():
    """Tasks management page"""
    logger.info("Serving tasks management page")
    return render_template("tasks.html", title="タスク管理")


@ui_bp.route("/approvals")
def approvals_page():
    """Approvals management page"""
    logger.info("Serving approvals management page")
    return render_template("approvals.html", title="承認管理")


@ui_bp.route("/ml")
def ml_page():
    """Machine Learning page"""
    logger.info("Serving ML page")
    return render_template("dashboard.html", title="機械学習")


@ui_bp.route("/ps1")
def ps1_page():
    """PowerShell scripts page"""
    logger.info("Serving PS1 page")
    return render_template("dashboard.html", title="PowerShellスクリプト")


@ui_bp.route("/results")
def results_page():
    """Results page"""
    logger.info("Serving results page")
    return render_template("dashboard.html", title="実行結果")


@ui_bp.route("/tasks/new")
def new_task_page():
    """New task creation page"""
    logger.info("Serving new task page")
    return render_template("dashboard.html", title="新規タスク作成")


@ui_bp.route("/realtime")
def realtime_page():
    """Real-time monitoring page"""
    logger.info("Serving realtime page")
    return render_template("dashboard.html", title="リアルタイム監視")


@ui_bp.route("/agents")
def agents_page():
    """Agents management page"""
    logger.info("Serving agents page")
    return render_template("agents.html", title="エージェント管理")


@ui_bp.route("/console")
def console_page():
    """Console page"""
    logger.info("Serving console page")
    return render_template("dashboard.html", title="コンソール")


@ui_bp.route("/monitoring")
def monitoring_page():
    """Monitoring page"""
    logger.info("Serving monitoring page")
    return render_template("dashboard.html", title="監視")


@ui_bp.route("/security")
def security_page():
    """Security page"""
    logger.info("Serving security page")
    return render_template("dashboard.html", title="セキュリティ")
