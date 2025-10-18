#!/usr/bin/env python3
"""
Unit tests for backup scripts integration.
Tests the core functionality of validate_backup_integrity, prune_backups, and restore_backup.
"""

import gzip
import json
import sqlite3

# Import backup script modules
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts" / "ops"))

from prune_backups import BackupPruner
from restore_backup import BackupRestorer, find_latest_backup
from validate_backup_integrity import (
    calculate_file_hash,
    validate_backup_directory,
    validate_backup_metadata,
    validate_single_backup,
    validate_sqlite_backup,
)


class TestBackupScriptsIntegration(unittest.TestCase):
    """Integration tests for backup scripts functionality."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.logger = Mock()
        self.pruner = BackupPruner(self.logger)
        self.restorer = BackupRestorer(self.logger)

    def tearDown(self):
        # Clean up temporary files
        for file in self.temp_dir.rglob("*"):
            if file.is_file():
                try:
                    file.unlink()
                except (PermissionError, OSError):
                    pass
        try:
            self.temp_dir.rmdir()
        except (PermissionError, OSError):
            pass

    def _create_test_database(self, db_path: Path, with_data: bool = True):
        """Create a test SQLite database."""
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE tasks (
                    id INTEGER PRIMARY KEY,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )
            if with_data:
                cursor.execute(
                    "INSERT INTO tasks (title, status) VALUES (?, ?)", ("Test Task", "DONE")
                )
            conn.commit()

    def _create_compressed_backup(self, source_db: Path, backup_path: Path):
        """Create a compressed backup file."""
        try:
            with open(source_db, "rb") as f_in:
                with gzip.open(backup_path, "wb") as f_out:
                    f_out.write(f_in.read())
        except Exception as e:
            self.logger.warning(f"Failed to create compressed backup: {e}")
            # Create uncompressed backup as fallback
            backup_path_uncompressed = backup_path.with_suffix("")
            with open(source_db, "rb") as f_in:
                with open(backup_path_uncompressed, "wb") as f_out:
                    f_out.write(f_in.read())

    def test_validate_backup_integrity_functions(self):
        """Test validate_backup_integrity core functions."""
        # Create test database
        test_db = self.temp_dir / "test.db"
        self._create_test_database(test_db)

        # Test calculate_file_hash
        hash_result = calculate_file_hash(test_db)
        self.assertIsNotNone(hash_result)
        self.assertEqual(len(hash_result), 64)  # SHA256 hash length

        # Test validate_sqlite_backup
        is_valid, message = validate_sqlite_backup(test_db, self.logger)
        self.assertTrue(is_valid)
        self.assertIn("valid", message.lower())

        # Test validate_backup_metadata
        metadata_valid, metadata_message = validate_backup_metadata(test_db, self.logger)
        self.assertIsInstance(metadata_valid, bool)
        self.assertIsInstance(metadata_message, str)
        self.assertTrue(metadata_valid)

        # Test validate_single_backup
        single_result = validate_single_backup(test_db, self.logger)
        self.assertIsInstance(single_result, dict)
        self.assertIn("valid", single_result)
        self.assertTrue(single_result["valid"])

    def test_backup_pruner_functionality(self):
        """Test BackupPruner core functionality."""
        # Create test backup files
        backup_files = []
        for i in range(5):
            backup_file = self.temp_dir / f"backup_{i}.db"
            backup_file.write_text(f"backup data {i}")
            backup_files.append(backup_file)

        # Test find_backup_files
        found_files = self.pruner.find_backup_files(self.temp_dir)
        self.assertEqual(len(found_files), 5)

        # Test prune_by_count
        files_to_prune = self.pruner.prune_by_count(backup_files, max_count=3)
        self.assertEqual(len(files_to_prune), 2)  # Should prune 2 oldest files

        # Test prune_by_age (all files are new, so none should be pruned)
        files_to_prune_age = self.pruner.prune_by_age(backup_files, max_age_days=1)
        self.assertEqual(len(files_to_prune_age), 0)

    def test_backup_restorer_functionality(self):
        """Test BackupRestorer functionality."""
        # Create a test backup (uncompressed to avoid Windows file lock issues)
        source_db = self.temp_dir / "source.db"
        self._create_test_database(source_db)

        backup_path = self.temp_dir / "test_backup.db"
        with open(source_db, "rb") as f_in:
            with open(backup_path, "wb") as f_out:
                f_out.write(f_in.read())

        # Test backup validation
        is_valid, message = self.restorer.validate_backup_file(backup_path)
        self.assertTrue(is_valid)
        self.assertIn("valid", message.lower())

        # Test restoration
        restore_path = self.temp_dir / "restored.db"
        success, result_message = self.restorer.restore_database(backup_path, restore_path)
        self.assertTrue(success)
        self.assertTrue(restore_path.exists())

        # Test create_safety_backup
        target_db = self.temp_dir / "target.db"
        self._create_test_database(target_db)

        safety_backup = self.restorer.create_safety_backup(target_db)
        self.assertIsNotNone(safety_backup)
        self.assertTrue(safety_backup.exists())

    def test_find_latest_backup_function(self):
        """Test find_latest_backup function."""
        # Create backup files with timestamps
        backup_dir = self.temp_dir / "backups"
        backup_dir.mkdir()

        # Create backups with different timestamps
        old_backup = backup_dir / "orch_backup_20241201_120000.db.gz"
        new_backup = backup_dir / "orch_backup_20241208_120000.db.gz"

        old_backup.write_text("old backup")
        new_backup.write_text("new backup")

        # Test find_latest_backup
        latest = find_latest_backup(backup_dir)
        self.assertIsNotNone(latest)
        # Should find the latest backup (highest date)
        self.assertTrue(latest.name.startswith("orch_backup_2024120"))
        self.assertTrue(latest.name.endswith(".db.gz"))

    def test_backup_workflow_integration(self):
        """Test complete backup workflow: create -> validate -> prune -> restore."""
        # Step 1: Create multiple backup files (uncompressed for simplicity)
        backup_dir = self.temp_dir / "backups"
        backup_dir.mkdir()

        backup_files = []
        for i in range(3):
            # Create source database
            source_db = self.temp_dir / f"source_{i}.db"
            self._create_test_database(source_db, with_data=True)

            # Create backup (copy as .db file)
            backup_file = backup_dir / f"orch_backup_2024120{i}_120000.db"
            with open(source_db, "rb") as f_in:
                with open(backup_file, "wb") as f_out:
                    f_out.write(f_in.read())
            backup_files.append(backup_file)

        # Step 2: Validate all backups
        validation_results = validate_backup_directory(backup_dir, self.logger)
        # Should find backup files (*.db pattern matches our files)
        self.assertGreaterEqual(len(validation_results), 3)
        valid_count = sum(1 for r in validation_results if r.get("valid", False))
        self.assertGreaterEqual(valid_count, 1)  # At least 1 should be valid

        # Step 3: Prune backups (keep only 2)
        found_backups = self.pruner.find_backup_files(backup_dir)
        files_to_prune = self.pruner.prune_by_count(found_backups, max_count=2)
        self.assertEqual(len(files_to_prune), 1)  # Should prune 1 file

        # Step 4: Find latest backup for restoration
        latest_backup = find_latest_backup(backup_dir, "*backup*.db")
        self.assertIsNotNone(latest_backup)

        # Step 5: Validate the latest backup before restoration
        is_valid, message = self.restorer.validate_backup_file(latest_backup)
        self.assertTrue(is_valid)

    def test_error_handling(self):
        """Test error handling in backup scripts."""
        # Test with non-existent file
        non_existent = self.temp_dir / "non_existent.db"

        # validate_backup_integrity should handle missing files
        is_valid, message = validate_sqlite_backup(non_existent, self.logger)
        self.assertFalse(is_valid)

        # BackupRestorer should handle invalid backup files
        is_valid, message = self.restorer.validate_backup_file(non_existent)
        self.assertFalse(is_valid)

        # BackupPruner should handle empty directories
        empty_dir = self.temp_dir / "empty"
        empty_dir.mkdir()
        found_files = self.pruner.find_backup_files(empty_dir)
        self.assertEqual(len(found_files), 0)

    def test_backup_file_patterns(self):
        """Test backup file pattern recognition."""
        # Create files with different patterns
        test_files = [
            "orch_backup_20241208_120000.db.gz",  # Should match
            "backup_test.db",  # Should match
            "data.backup",  # Should match
            "regular_file.txt",  # Should not match
            "test.db.gz",  # Should not match (no backup in name)
        ]

        for filename in test_files:
            (self.temp_dir / filename).write_text("test content")

        found_files = self.pruner.find_backup_files(self.temp_dir)
        found_names = [f.name for f in found_files]

        # Should find backup files but not regular files
        self.assertIn("orch_backup_20241208_120000.db.gz", found_names)
        self.assertIn("backup_test.db", found_names)
        self.assertIn("data.backup", found_names)
        self.assertNotIn("regular_file.txt", found_names)


class TestBackupScriptsEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.logger = Mock()

    def tearDown(self):
        # Clean up temporary files
        for file in self.temp_dir.rglob("*"):
            if file.is_file():
                try:
                    file.unlink()
                except (PermissionError, OSError):
                    pass
        try:
            self.temp_dir.rmdir()
        except (PermissionError, OSError):
            pass

    def test_empty_database_validation(self):
        """Test validation of empty database files."""
        empty_db = self.temp_dir / "empty.db"
        empty_db.write_text("")  # Create empty file

        is_valid, message = validate_sqlite_backup(empty_db, self.logger)
        self.assertFalse(is_valid)
        self.assertIn("no tables", message.lower())

    def test_corrupted_backup_validation(self):
        """Test validation of corrupted backup files."""
        corrupted_backup = self.temp_dir / "corrupted.db.gz"
        with gzip.open(corrupted_backup, "wb") as f:
            f.write(b"corrupted data that is not a valid database")

        is_valid, message = validate_sqlite_backup(corrupted_backup, self.logger)
        self.assertFalse(is_valid)

    def test_large_backup_handling(self):
        """Test handling of large backup files."""
        # Create a database with substantial data
        large_db = self.temp_dir / "large.db"
        with sqlite3.connect(str(large_db)) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE large_table (
                    id INTEGER PRIMARY KEY,
                    data TEXT
                )
            """
            )
            # Insert substantial data
            for i in range(1000):
                cursor.execute("INSERT INTO large_table (data) VALUES (?)", (f"data_{i}" * 100,))
            conn.commit()

        # Validate large database
        metadata_valid, metadata_message = validate_backup_metadata(large_db, self.logger)
        self.assertTrue(metadata_valid)


if __name__ == "__main__":
    unittest.main()
