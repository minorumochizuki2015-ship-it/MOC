#!/usr/bin/env python3
"""
Backup Restoration Script

Restores database and system state from backup files.
Includes safety checks, rollback capability, and verification.
"""

import argparse
import gzip
import json
import logging
import shutil
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level, format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    return logging.getLogger(__name__)


class BackupRestorer:
    """Handles backup restoration with safety checks and rollback."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.backup_created = []  # Track backups created during restore

    def validate_backup_file(self, backup_path: Path) -> Tuple[bool, str]:
        """Validate backup file before restoration."""
        if not backup_path.exists():
            return False, f"Backup file does not exist: {backup_path}"

        if backup_path.stat().st_size == 0:
            return False, "Backup file is empty"

        # For SQLite backups, try to validate structure
        if backup_path.name.endswith((".db", ".db.gz")):
            return self._validate_sqlite_backup(backup_path)

        return True, "Backup file validation passed"

    def _validate_sqlite_backup(self, backup_path: Path) -> Tuple[bool, str]:
        """Validate SQLite backup file."""
        try:
            temp_db = None

            if backup_path.suffix == ".gz":
                # Create temporary uncompressed file
                temp_db = backup_path.with_suffix(".tmp")
                with gzip.open(backup_path, "rb") as gz_file:
                    with open(temp_db, "wb") as temp_file:
                        temp_file.write(gz_file.read())
                db_to_check = temp_db
            else:
                db_to_check = backup_path

            # Test database connection and integrity
            with sqlite3.connect(str(db_to_check)) as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA integrity_check")
                result = cursor.fetchone()[0]

                if result != "ok":
                    return False, f"SQLite integrity check failed: {result}"

                # Check for tables
                cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
                table_count = cursor.fetchone()[0]

                if table_count == 0:
                    return False, "Database contains no tables"

            # Clean up temporary file
            if temp_db and temp_db.exists():
                # Windows でのロック耐性: 一時ファイル削除にリトライ
                for _ in range(5):
                    try:
                        temp_db.unlink()
                        break
                    except (PermissionError, OSError):
                        time.sleep(0.2)
                else:
                    # 最終手段: 削除失敗をログに出すが検証自体は成功とする
                    self.logger.warning(f"Failed to delete temp file after validation: {temp_db}")

            return True, f"Validation passed: valid SQLite database with {table_count} tables"

        except Exception as e:
            # Clean up temporary file on error (Windows 耐性のためリトライ)
            if temp_db and temp_db.exists():
                for _ in range(5):
                    try:
                        temp_db.unlink()
                        break
                    except (PermissionError, OSError):
                        time.sleep(0.2)
                else:
                    self.logger.warning(f"Failed to delete temp file after error: {temp_db}")
            return False, f"SQLite validation failed: {e}"

    def create_safety_backup(self, target_path: Path) -> Optional[Path]:
        """Create safety backup of current file before restoration."""
        if not target_path.exists():
            self.logger.info(f"Target file does not exist, no safety backup needed: {target_path}")
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safety_backup = target_path.with_suffix(f".pre_restore_{timestamp}{target_path.suffix}")

        try:
            shutil.copy2(target_path, safety_backup)
            self.backup_created.append(safety_backup)
            self.logger.info(f"Safety backup created: {safety_backup}")
            return safety_backup
        except Exception as e:
            self.logger.error(f"Failed to create safety backup: {e}")
            return None

    def restore_database(
        self, backup_path: Path, target_path: Path, verify: bool = True
    ) -> Tuple[bool, str]:
        """Restore database from backup file."""
        self.logger.info(f"Restoring database from {backup_path} to {target_path}")

        # Validate backup file
        valid, msg = self.validate_backup_file(backup_path)
        if not valid:
            return False, f"Backup validation failed: {msg}"

        # Create safety backup
        safety_backup = self.create_safety_backup(target_path)

        try:
            # Ensure target directory exists
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # Restore from backup
            if backup_path.suffix == ".gz":
                # Decompress and restore
                with gzip.open(backup_path, "rb") as gz_file:
                    with open(target_path, "wb") as target_file:
                        shutil.copyfileobj(gz_file, target_file)
            else:
                # Direct copy
                shutil.copy2(backup_path, target_path)

            self.logger.info(f"Database restored to: {target_path}")

            # Verify restored database if requested
            if verify:
                verify_success, verify_msg = self._verify_restored_database(target_path)
                if not verify_success:
                    # Restore failed verification, rollback
                    if safety_backup:
                        shutil.copy2(safety_backup, target_path)
                        self.logger.error(
                            "Restored database failed verification, rolled back to original"
                        )
                    return False, f"Verification failed: {verify_msg}"

            return True, "Database restoration completed successfully"

        except Exception as e:
            # Restore original database if available
            if safety_backup and safety_backup.exists():
                try:
                    shutil.copy2(safety_backup, target_path)
                    self.logger.error("Restoration failed, rolled back to original database")
                except Exception as rollback_error:
                    self.logger.error(f"Rollback also failed: {rollback_error}")

            return False, f"Restoration failed: {e}"

    def _verify_restored_database(self, db_path: Path) -> Tuple[bool, str]:
        """Verify restored database integrity."""
        try:
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()

                # Run integrity check
                cursor.execute("PRAGMA integrity_check")
                result = cursor.fetchone()[0]

                if result != "ok":
                    return False, f"Integrity check failed: {result}"

                # Basic functionality test
                cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
                table_count = cursor.fetchone()[0]

                self.logger.info(f"Database verification passed: {table_count} tables found")
                return True, f"Verification successful ({table_count} tables)"

        except Exception as e:
            return False, f"Verification error: {e}"

    def cleanup_safety_backups(self, keep_backups: bool = False):
        """Clean up safety backups created during restoration."""
        if keep_backups:
            self.logger.info(f"Keeping {len(self.backup_created)} safety backups")
            return

        for backup_path in self.backup_created:
            try:
                if backup_path.exists():
                    # Windows でのロック耐性: 安全バックアップ削除にリトライ
                    for _ in range(5):
                        try:
                            backup_path.unlink()
                            break
                        except (PermissionError, OSError):
                            time.sleep(0.2)
                    else:
                        self.logger.warning(
                            f"Failed to delete safety backup (locked): {backup_path}"
                        )
                    self.logger.debug(f"Cleaned up safety backup: {backup_path}")
            except Exception as e:
                self.logger.warning(f"Failed to clean up safety backup {backup_path}: {e}")

        if self.backup_created:
            self.logger.info(f"Cleaned up {len(self.backup_created)} safety backups")


def find_latest_backup(backup_dir: Path, pattern: str = "*backup*.db.gz") -> Optional[Path]:
    """Find the most recent backup file in directory."""
    if not backup_dir.exists():
        return None

    backup_files = list(backup_dir.glob(pattern))
    if not backup_files:
        return None

    # Sort by modification time, newest first
    backup_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
    return backup_files[0]


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Restore database from backup")
    parser.add_argument("backup_file", nargs="?", help="Backup file to restore from")
    parser.add_argument("-t", "--target", help="Target database file path (default: data/orch.db)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument(
        "--no-verify", action="store_true", help="Skip verification of restored database"
    )
    parser.add_argument(
        "--keep-safety-backup", action="store_true", help="Keep safety backup files"
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        help="Directory to search for latest backup (if backup_file not specified)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be done without actually restoring"
    )
    parser.add_argument("--report", type=Path, help="Save restoration report to file")

    args = parser.parse_args()

    logger = setup_logging(args.verbose)

    # Determine backup file
    if args.backup_file:
        backup_path = Path(args.backup_file)
    elif args.backup_dir:
        backup_path = find_latest_backup(args.backup_dir)
        if not backup_path:
            logger.error(f"No backup files found in: {args.backup_dir}")
            sys.exit(1)
            return
        logger.info(f"Using latest backup: {backup_path}")
    else:
        # Default backup directory (relative to current working directory)
        default_backup_dir = Path.cwd() / "data" / "backups"
        backup_path = find_latest_backup(default_backup_dir)
        if not backup_path:
            logger.error(f"No backup files found in default directory: {default_backup_dir}")
            logger.error("Please specify backup file or backup directory")
            sys.exit(1)
            return
        logger.info(f"Using latest backup from default directory: {backup_path}")

    # Determine target path
    target_path = Path(args.target) if args.target else Path("data/orch.db")

    logger.info(f"Restoration plan:")
    logger.info(f"  Source: {backup_path}")
    logger.info(f"  Target: {target_path}")
    logger.info(f"  Verify: {not args.no_verify}")
    logger.info(f"  Keep safety backup: {args.keep_safety_backup}")

    if args.dry_run:
        logger.info("[DRY RUN] Would perform restoration with above settings")
        sys.exit(0)
        return

    # Initialize restorer
    restorer = BackupRestorer(logger)

    # Perform restoration
    start_time = datetime.now()
    success, message = restorer.restore_database(
        backup_path, target_path, verify=not args.no_verify
    )
    end_time = datetime.now()

    # Generate report
    report = {
        "timestamp": start_time.isoformat(),
        "duration_seconds": (end_time - start_time).total_seconds(),
        "backup_file": str(backup_path),
        "target_file": str(target_path),
        "success": success,
        "message": message,
        "verification_enabled": not args.no_verify,
        "safety_backups_created": [str(p) for p in restorer.backup_created],
    }

    # Save report if requested
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with open(args.report, "w") as f:
            json.dump(report, f, indent=2)
        logger.info(f"Report saved to: {args.report}")

    # Clean up safety backups if requested
    restorer.cleanup_safety_backups(keep_backups=args.keep_safety_backup)

    # Log final result
    if success:
        logger.info(f"✓ Restoration completed successfully: {message}")
        sys.exit(0)
        return
    else:
        logger.error(f"✗ Restoration failed: {message}")
        sys.exit(1)
        return


if __name__ == "__main__":
    main()
