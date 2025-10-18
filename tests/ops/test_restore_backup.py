#!/usr/bin/env python3
"""
Unit tests for restore_backup.py script.
Tests backup restoration functionality with comprehensive coverage.
"""

import gzip
import json
import sqlite3

# Import the module under test
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from tests_helpers import cleanup_temp_dir

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts" / "ops"))
from restore_backup import BackupRestorer, find_latest_backup, main, setup_logging


class TestBackupRestorer(unittest.TestCase):
    """Test BackupRestorer class functionality."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.logger = Mock()
        self.restorer = BackupRestorer(self.logger)

    def tearDown(self):
        cleanup_temp_dir(self.temp_dir)

    def _create_test_database(self, db_path: Path, with_data: bool = True):
        """Helper to create a test SQLite database."""
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE test_table (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            if with_data:
                cursor.execute("INSERT INTO test_table (name) VALUES (?)", ("test_record",))

            conn.commit()

    def _create_compressed_backup(self, source_db: Path, backup_path: Path):
        """Helper to create a compressed backup from a database."""
        with open(source_db, "rb") as f_in:
            with gzip.open(backup_path, "wb") as f_out:
                f_out.write(f_in.read())

    def test_validate_backup_file_valid_uncompressed(self):
        """Test validation of valid uncompressed backup file."""
        db_path = self.temp_dir / "test.db"
        self._create_test_database(db_path)

        is_valid, message = self.restorer.validate_backup_file(db_path)

        self.assertTrue(is_valid)
        self.assertIn("validation passed", message.lower())

    def test_validate_backup_file_valid_compressed(self):
        """Test validation of valid compressed backup file."""
        db_path = self.temp_dir / "test.db"
        compressed_path = self.temp_dir / "test.db.gz"

        self._create_test_database(db_path)
        self._create_compressed_backup(db_path, compressed_path)

        is_valid, message = self.restorer.validate_backup_file(compressed_path)

        self.assertTrue(is_valid)
        self.assertIn("valid sqlite database", message.lower())

    def test_validate_backup_file_nonexistent(self):
        """Test validation of non-existent backup file."""
        nonexistent_path = self.temp_dir / "nonexistent.db"

        is_valid, message = self.restorer.validate_backup_file(nonexistent_path)

        self.assertFalse(is_valid)
        self.assertIn("does not exist", message.lower())

    def test_validate_backup_file_empty(self):
        """Test validation of empty backup file."""
        empty_path = self.temp_dir / "empty.db"
        empty_path.touch()

        is_valid, message = self.restorer.validate_backup_file(empty_path)

        self.assertFalse(is_valid)
        self.assertIn("empty", message.lower())

    def test_validate_backup_file_corrupted(self):
        """Test validation of corrupted backup file."""
        corrupted_path = self.temp_dir / "corrupted.db"
        corrupted_path.write_text("This is not a valid SQLite database")

        is_valid, message = self.restorer.validate_backup_file(corrupted_path)

        self.assertFalse(is_valid)
        self.assertIn("validation failed", message.lower())

    def test_validate_sqlite_backup_valid(self):
        """Test SQLite backup validation for valid database."""
        db_path = self.temp_dir / "test.db"
        self._create_test_database(db_path)

        is_valid, message = self.restorer._validate_sqlite_backup(db_path)

        self.assertTrue(is_valid)
        self.assertIn("valid sqlite database", message.lower())
        self.assertIn("tables", message.lower())

    def test_validate_sqlite_backup_compressed(self):
        """Test SQLite backup validation for compressed database."""
        db_path = self.temp_dir / "test.db"
        compressed_path = self.temp_dir / "test.db.gz"

        self._create_test_database(db_path)
        self._create_compressed_backup(db_path, compressed_path)

        is_valid, message = self.restorer._validate_sqlite_backup(compressed_path)

        self.assertTrue(is_valid)
        self.assertIn("valid sqlite database", message.lower())

    def test_validate_sqlite_backup_no_tables(self):
        """Test SQLite backup validation for database with no tables."""
        db_path = self.temp_dir / "empty.db"
        # Create empty database
        with sqlite3.connect(str(db_path)) as conn:
            pass  # Just create the file

        is_valid, message = self.restorer._validate_sqlite_backup(db_path)

        self.assertFalse(is_valid)
        self.assertIn("no tables", message.lower())

    def test_validate_sqlite_backup_corrupted(self):
        """Test SQLite backup validation for corrupted database."""
        corrupted_path = self.temp_dir / "corrupted.db"
        corrupted_path.write_text("Not a SQLite database")

        is_valid, message = self.restorer._validate_sqlite_backup(corrupted_path)

        self.assertFalse(is_valid)
        self.assertIn("validation failed", message.lower())

    def test_create_safety_backup_success(self):
        """Test successful creation of safety backup."""
        original_db = self.temp_dir / "original.db"
        self._create_test_database(original_db)

        safety_backup = self.restorer.create_safety_backup(original_db)

        self.assertIsNotNone(safety_backup)
        self.assertTrue(safety_backup.exists())
        self.assertIn("pre_restore", safety_backup.name)
        self.assertIn(safety_backup, self.restorer.backup_created)

    def test_create_safety_backup_nonexistent_file(self):
        """Test safety backup creation for non-existent file."""
        nonexistent_db = self.temp_dir / "nonexistent.db"

        safety_backup = self.restorer.create_safety_backup(nonexistent_db)

        self.assertIsNone(safety_backup)
        self.assertEqual(len(self.restorer.backup_created), 0)

    def test_restore_database_uncompressed_success(self):
        """Test successful restoration from uncompressed backup."""
        # Create source backup
        backup_db = self.temp_dir / "backup.db"
        self._create_test_database(backup_db)

        # Target location
        target_db = self.temp_dir / "restored.db"

        success, message = self.restorer.restore_database(backup_db, target_db)

        self.assertTrue(success)
        self.assertTrue(target_db.exists())
        self.assertIn("completed successfully", message.lower())

        # Verify restored database is functional
        with sqlite3.connect(str(target_db)) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM test_table")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 1)

    def test_restore_database_compressed_success(self):
        """Test successful restoration from compressed backup."""
        # Create source database and compress it
        source_db = self.temp_dir / "source.db"
        backup_gz = self.temp_dir / "backup.db.gz"

        self._create_test_database(source_db)
        self._create_compressed_backup(source_db, backup_gz)

        # Target location
        target_db = self.temp_dir / "restored.db"

        success, message = self.restorer.restore_database(backup_gz, target_db)

        self.assertTrue(success)
        self.assertTrue(target_db.exists())

        # Verify restored database is functional
        with sqlite3.connect(str(target_db)) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM test_table")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 1)

    def test_restore_database_with_existing_target(self):
        """Test restoration when target file already exists."""
        # Create backup
        backup_db = self.temp_dir / "backup.db"
        self._create_test_database(backup_db)

        # Create existing target
        target_db = self.temp_dir / "existing.db"
        target_db.write_text("existing content")

        success, message = self.restorer.restore_database(backup_db, target_db)

        self.assertTrue(success)

        # Verify safety backup was created
        self.assertEqual(len(self.restorer.backup_created), 1)
        safety_backup = self.restorer.backup_created[0]
        self.assertTrue(safety_backup.exists())
        self.assertIn("pre_restore", safety_backup.name)

    def test_restore_database_invalid_backup(self):
        """Test restoration with invalid backup file."""
        # Create invalid backup
        invalid_backup = self.temp_dir / "invalid.db"
        invalid_backup.write_text("not a database")

        target_db = self.temp_dir / "target.db"

        success, message = self.restorer.restore_database(invalid_backup, target_db)

        self.assertFalse(success)
        self.assertIn("validation failed", message.lower())
        self.assertFalse(target_db.exists())

    def test_restore_database_verification_failure(self):
        """Test restoration with verification failure."""
        # Create backup that will fail verification
        backup_db = self.temp_dir / "backup.db"
        backup_db.write_text("fake database content")

        target_db = self.temp_dir / "target.db"

        # Mock validation to pass initially but fail verification
        with patch.object(self.restorer, "validate_backup_file", return_value=(True, "OK")):
            with patch.object(
                self.restorer,
                "_verify_restored_database",
                return_value=(False, "Verification failed"),
            ):
                success, message = self.restorer.restore_database(backup_db, target_db, verify=True)

        self.assertFalse(success)
        self.assertIn("verification failed", message.lower())

    def test_restore_database_no_verification(self):
        """Test restoration without verification."""
        backup_db = self.temp_dir / "backup.db"
        self._create_test_database(backup_db)

        target_db = self.temp_dir / "target.db"

        success, message = self.restorer.restore_database(backup_db, target_db, verify=False)

        self.assertTrue(success)
        self.assertTrue(target_db.exists())

    def test_verify_restored_database_success(self):
        """Test successful database verification."""
        db_path = self.temp_dir / "test.db"
        self._create_test_database(db_path)

        is_valid, message = self.restorer._verify_restored_database(db_path)

        self.assertTrue(is_valid)
        self.assertIn("verification successful", message.lower())

    def test_verify_restored_database_corrupted(self):
        """Test verification of corrupted database."""
        corrupted_db = self.temp_dir / "corrupted.db"
        corrupted_db.write_text("not a database")

        is_valid, message = self.restorer._verify_restored_database(corrupted_db)

        self.assertFalse(is_valid)
        self.assertIn("verification error", message.lower())

    def test_cleanup_safety_backups_remove(self):
        """Test cleanup of safety backups (remove mode)."""
        # Create some safety backups
        backup1 = self.temp_dir / "safety1.db"
        backup2 = self.temp_dir / "safety2.db"

        backup1.write_text("safety backup 1")
        backup2.write_text("safety backup 2")

        self.restorer.backup_created = [backup1, backup2]

        self.restorer.cleanup_safety_backups(keep_backups=False)

        self.assertFalse(backup1.exists())
        self.assertFalse(backup2.exists())

    def test_cleanup_safety_backups_keep(self):
        """Test cleanup of safety backups (keep mode)."""
        # Create some safety backups
        backup1 = self.temp_dir / "safety1.db"
        backup2 = self.temp_dir / "safety2.db"

        backup1.write_text("safety backup 1")
        backup2.write_text("safety backup 2")

        self.restorer.backup_created = [backup1, backup2]

        self.restorer.cleanup_safety_backups(keep_backups=True)

        self.assertTrue(backup1.exists())
        self.assertTrue(backup2.exists())


class TestFindLatestBackup(unittest.TestCase):
    """Test find_latest_backup function."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        cleanup_temp_dir(self.temp_dir)

    def _create_backup_file(self, name: str, age_minutes: int = 0) -> Path:
        """Helper to create a backup file with specific age."""
        backup_path = self.temp_dir / name
        backup_path.write_text("backup content")

        if age_minutes > 0:
            import os
            import time

            old_time = time.time() - (age_minutes * 60)
            # Path.touch does not support 'times' kwarg; use os.utime to set atime/mtime
            os.utime(backup_path, (old_time, old_time))

        return backup_path

    def test_find_latest_backup_success(self):
        """Test finding latest backup in directory."""
        # Create backups with different ages
        old_backup = self._create_backup_file("old_backup.db.gz", age_minutes=60)
        recent_backup = self._create_backup_file("recent_backup.db.gz", age_minutes=10)
        latest_backup = self._create_backup_file("latest_backup.db.gz", age_minutes=0)

        latest = find_latest_backup(self.temp_dir)

        self.assertEqual(latest, latest_backup)

    def test_find_latest_backup_custom_pattern(self):
        """Test finding latest backup with custom pattern."""
        # Create different types of files
        self._create_backup_file("backup.db.gz")
        custom_backup = self._create_backup_file("custom.bak")
        self._create_backup_file("other.txt")

        latest = find_latest_backup(self.temp_dir, pattern="*.bak")

        self.assertEqual(latest, custom_backup)

    def test_find_latest_backup_no_files(self):
        """Test finding latest backup when no matching files exist."""
        # Create non-matching files
        self._create_backup_file("other.txt")

        latest = find_latest_backup(self.temp_dir)

        self.assertIsNone(latest)

    def test_find_latest_backup_nonexistent_directory(self):
        """Test finding latest backup in non-existent directory."""
        nonexistent_dir = self.temp_dir / "nonexistent"

        latest = find_latest_backup(nonexistent_dir)

        self.assertIsNone(latest)


class TestSetupLogging(unittest.TestCase):
    """Test logging setup function."""

    def test_setup_logging_default(self):
        """Test default logging setup."""
        logger = setup_logging()

        self.assertIsNotNone(logger)
        self.assertEqual(logger.level, 0)  # Logger inherits from root

    def test_setup_logging_verbose(self):
        """Test verbose logging setup."""
        logger = setup_logging(verbose=True)

        self.assertIsNotNone(logger)


class TestMainFunction(unittest.TestCase):
    """Test main function and CLI interface."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        cleanup_temp_dir(self.temp_dir)

    def _create_test_database(self, db_path: Path):
        """Helper to create a test SQLite database."""
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE test_table (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL
                )
            """
            )
            cursor.execute("INSERT INTO test_table (name) VALUES (?)", ("test",))
            conn.commit()

    @patch("sys.argv")
    @patch("restore_backup.setup_logging")
    def test_main_restore_success(self, mock_logging, mock_argv):
        """Test main function with successful restoration."""
        # Create backup file
        backup_file = self.temp_dir / "backup.db"
        self._create_test_database(backup_file)

        target_file = self.temp_dir / "restored.db"

        # Mock command line arguments
        mock_argv.__getitem__.side_effect = lambda i: [
            "restore_backup.py",
            str(backup_file),
            "--target",
            str(target_file),
        ][i]
        mock_argv.__len__.return_value = 4

        # Mock logger
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        # Test main function
        with patch("sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_with(0)  # Success exit code

        # Verify target file was created
        self.assertTrue(target_file.exists())

    @patch("sys.argv")
    @patch("restore_backup.setup_logging")
    def test_main_find_latest_backup(self, mock_logging, mock_argv):
        """Test main function finding latest backup automatically."""
        # Create backup directory with backups
        backup_dir = self.temp_dir / "data" / "backups"
        backup_dir.mkdir(parents=True)

        backup_file = backup_dir / "orch_backup_20241208.db.gz"
        source_db = self.temp_dir / "source.db"
        self._create_test_database(source_db)

        # Create compressed backup
        with open(source_db, "rb") as f_in:
            with gzip.open(backup_file, "wb") as f_out:
                f_out.write(f_in.read())

        # Mock command line arguments (no backup file specified)
        mock_argv.__getitem__.side_effect = lambda i: ["restore_backup.py"][i]
        mock_argv.__len__.return_value = 1

        # Mock logger
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        # Change working directory context
        with patch("pathlib.Path.cwd", return_value=self.temp_dir):
            with patch("sys.exit") as mock_exit:
                main()
                mock_exit.assert_called_with(0)

    @patch("sys.argv")
    @patch("restore_backup.setup_logging")
    def test_main_dry_run(self, mock_logging, mock_argv):
        """Test main function in dry run mode."""
        backup_file = self.temp_dir / "backup.db"
        self._create_test_database(backup_file)

        # Mock command line arguments
        mock_argv.__getitem__.side_effect = lambda i: [
            "restore_backup.py",
            str(backup_file),
            "--dry-run",
        ][i]
        mock_argv.__len__.return_value = 3

        # Mock logger
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        # Test main function
        with patch("sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_with(0)

    @patch("sys.argv")
    @patch("restore_backup.setup_logging")
    def test_main_with_report_output(self, mock_logging, mock_argv):
        """Test main function with JSON report output."""
        backup_file = self.temp_dir / "backup.db"
        self._create_test_database(backup_file)

        target_file = self.temp_dir / "restored.db"
        report_file = self.temp_dir / "restore_report.json"

        # Mock command line arguments
        mock_argv.__getitem__.side_effect = lambda i: [
            "restore_backup.py",
            str(backup_file),
            "--target",
            str(target_file),
            "--report",
            str(report_file),
        ][i]
        mock_argv.__len__.return_value = 6

        # Mock logger
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        # Test main function
        with patch("sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_with(0)

        # Verify report file was created
        self.assertTrue(report_file.exists())

        # Verify report content
        with open(report_file) as f:
            report_data = json.load(f)

        self.assertIn("success", report_data)
        self.assertIn("backup_file", report_data)
        self.assertIn("target_file", report_data)
        self.assertIn("timestamp", report_data)

    @patch("sys.argv")
    @patch("restore_backup.setup_logging")
    def test_main_no_backup_found(self, mock_logging, mock_argv):
        """Test main function when no backup is found."""
        # Mock command line arguments (no backup file, no backup directory)
        mock_argv.__getitem__.side_effect = lambda i: ["restore_backup.py"][i]
        mock_argv.__len__.return_value = 1

        # Mock logger
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        # Test main function
        with patch("sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_with(1)  # Error exit code


class TestIntegrationScenarios(unittest.TestCase):
    """Integration tests for realistic backup restoration scenarios."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.logger = Mock()
        self.restorer = BackupRestorer(self.logger)

    def tearDown(self):
        cleanup_temp_dir(self.temp_dir)

    def _create_realistic_database(self, db_path: Path):
        """Create a realistic database with multiple tables and data."""
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()

            # Create tasks table
            cursor.execute(
                """
                CREATE TABLE tasks (
                    id INTEGER PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL,
                    priority INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Create users table
            cursor.execute(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Insert sample data
            cursor.execute(
                """
                INSERT INTO tasks (title, description, status, priority) 
                VALUES (?, ?, ?, ?)
            """,
                ("Test Task", "A test task for validation", "DONE", 1),
            )

            cursor.execute(
                """
                INSERT INTO users (username, email) 
                VALUES (?, ?)
            """,
                ("testuser", "test@example.com"),
            )

            conn.commit()

    def test_realistic_database_restoration(self):
        """Test restoration of realistic database backup."""
        # Create source database
        source_db = self.temp_dir / "source.db"
        self._create_realistic_database(source_db)

        # Create compressed backup
        backup_gz = self.temp_dir / "backup.db.gz"
        with open(source_db, "rb") as f_in:
            with gzip.open(backup_gz, "wb") as f_out:
                f_out.write(f_in.read())

        # Restore to new location
        target_db = self.temp_dir / "restored.db"

        success, message = self.restorer.restore_database(backup_gz, target_db)

        self.assertTrue(success)
        self.assertTrue(target_db.exists())

        # Verify restored database content
        with sqlite3.connect(str(target_db)) as conn:
            cursor = conn.cursor()

            # Check tasks table
            cursor.execute("SELECT COUNT(*) FROM tasks")
            task_count = cursor.fetchone()[0]
            self.assertEqual(task_count, 1)

            # Check users table
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            self.assertEqual(user_count, 1)

            # Verify specific data
            cursor.execute("SELECT title FROM tasks WHERE id = 1")
            task_title = cursor.fetchone()[0]
            self.assertEqual(task_title, "Test Task")

    def test_restoration_with_rollback(self):
        """Test restoration with rollback on verification failure."""
        # Create valid backup
        source_db = self.temp_dir / "source.db"
        self._create_realistic_database(source_db)

        # Create existing target with different content
        target_db = self.temp_dir / "existing.db"
        with sqlite3.connect(str(target_db)) as conn:
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE original (id INTEGER PRIMARY KEY)")
            cursor.execute("INSERT INTO original (id) VALUES (1)")
            conn.commit()

        # Mock verification to fail
        with patch.object(
            self.restorer, "_verify_restored_database", return_value=(False, "Mock failure")
        ):
            success, message = self.restorer.restore_database(source_db, target_db)

        self.assertFalse(success)

        # Verify original database was restored
        with sqlite3.connect(str(target_db)) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            self.assertIn("original", tables)

    def test_disaster_recovery_scenario(self):
        """Test complete disaster recovery scenario."""
        # Simulate disaster recovery: restore from backup when main DB is corrupted

        # Create backup
        backup_db = self.temp_dir / "disaster_backup.db.gz"
        source_db = self.temp_dir / "source.db"
        self._create_realistic_database(source_db)

        with open(source_db, "rb") as f_in:
            with gzip.open(backup_db, "wb") as f_out:
                f_out.write(f_in.read())

        # Create corrupted main database
        main_db = self.temp_dir / "main.db"
        main_db.write_text("CORRUPTED DATABASE CONTENT")

        # Perform disaster recovery
        success, message = self.restorer.restore_database(backup_db, main_db)

        self.assertTrue(success)

        # Verify recovery was successful
        with sqlite3.connect(str(main_db)) as conn:
            cursor = conn.cursor()

            # Verify database is functional
            cursor.execute("PRAGMA integrity_check")
            integrity = cursor.fetchone()[0]
            self.assertEqual(integrity, "ok")

            # Verify data is present
            cursor.execute("SELECT COUNT(*) FROM tasks")
            task_count = cursor.fetchone()[0]
            self.assertGreater(task_count, 0)

        # Verify safety backup was created
        self.assertEqual(len(self.restorer.backup_created), 1)
        safety_backup = self.restorer.backup_created[0]
        self.assertTrue(safety_backup.exists())


if __name__ == "__main__":
    unittest.main()
