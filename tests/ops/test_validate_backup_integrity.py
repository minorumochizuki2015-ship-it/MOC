#!/usr/bin/env python3
"""
Unit tests for validate_backup_integrity.py script.
Tests backup validation functionality with comprehensive coverage.
"""

import gzip
import json
import shutil
import sqlite3

# Import the module under test
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from tests_helpers import cleanup_temp_dir

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts" / "ops"))
from validate_backup_integrity import (
    calculate_file_hash,
    main,
    setup_logging,
    validate_backup_directory,
    validate_backup_metadata,
    validate_single_backup,
    validate_sqlite_backup,
)


class TestCalculateFileHash(unittest.TestCase):
    """Test file hash calculation function."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        cleanup_temp_dir(self.temp_dir)

    def test_calculate_hash_normal_file(self):
        """Test hash calculation for normal file."""
        test_file = self.temp_dir / "test.txt"
        test_content = "Hello, World!"
        test_file.write_text(test_content)

        hash_value = calculate_file_hash(test_file)

        # Verify hash is returned and is a string
        self.assertIsInstance(hash_value, str)
        self.assertEqual(len(hash_value), 64)  # SHA256 hex length

    def test_calculate_hash_empty_file(self):
        """Test hash calculation for empty file."""
        test_file = self.temp_dir / "empty.txt"
        test_file.touch()

        hash_value = calculate_file_hash(test_file)

        # Empty file should still have a valid hash
        self.assertIsInstance(hash_value, str)
        self.assertEqual(len(hash_value), 64)

    def test_calculate_hash_nonexistent_file(self):
        """Test hash calculation for non-existent file."""
        nonexistent_file = self.temp_dir / "nonexistent.txt"

        hash_value = calculate_file_hash(nonexistent_file)

        self.assertIsNone(hash_value)


class TestValidateBackupIntegrity(unittest.TestCase):
    """Test backup validation functions."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.logger = Mock()

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

    def _create_compressed_database(self, db_path: Path, compressed_path: Path):
        """Helper to create a compressed database backup."""
        with open(db_path, "rb") as f_in:
            with gzip.open(compressed_path, "wb") as f_out:
                f_out.write(f_in.read())

    def test_validate_sqlite_backup_valid_uncompressed(self):
        """Test validation of valid uncompressed SQLite backup."""
        db_path = self.temp_dir / "test.db"
        self._create_test_database(db_path)

        is_valid, message = validate_sqlite_backup(db_path, self.logger)

        self.assertTrue(is_valid)
        self.assertIn("Valid SQLite database", message)

    def test_validate_sqlite_backup_valid_compressed(self):
        """Test validation of valid compressed SQLite backup."""
        db_path = self.temp_dir / "test.db"
        compressed_path = self.temp_dir / "test.db.gz"

        self._create_test_database(db_path)
        self._create_compressed_database(db_path, compressed_path)

        is_valid, message = validate_sqlite_backup(compressed_path, self.logger)

        self.assertTrue(is_valid)
        self.assertIn("Valid SQLite database", message)

    def test_validate_sqlite_backup_corrupted(self):
        """Test validation of corrupted SQLite backup."""
        corrupted_path = self.temp_dir / "corrupted.db"
        corrupted_path.write_text("This is not a valid SQLite database")

        is_valid, message = validate_sqlite_backup(corrupted_path, self.logger)

        self.assertFalse(is_valid)
        self.assertIn("validation failed", message.lower())

    def test_validate_sqlite_backup_empty_database(self):
        """Test validation of empty SQLite database."""
        db_path = self.temp_dir / "empty.db"
        self._create_test_database(db_path, with_data=False)

        # Remove the test table to make it truly empty
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("DROP TABLE test_table")
            conn.commit()

        is_valid, message = validate_sqlite_backup(db_path, self.logger)

        self.assertFalse(is_valid)
        self.assertIn("no tables", message.lower())

    def test_validate_backup_metadata_valid(self):
        """Test validation of backup metadata for valid file."""
        test_file = self.temp_dir / "backup.db"
        test_file.write_text("test backup content")

        is_valid, message = validate_backup_metadata(test_file, self.logger)

        self.assertTrue(is_valid)
        self.assertIn("Metadata validation passed", message)

    def test_validate_backup_metadata_too_old(self):
        """Test validation of backup metadata for old file."""
        test_file = self.temp_dir / "old_backup.db"
        test_file.write_text("old backup content")

        # Mock file modification time to be very old
        old_timestamp = (datetime.now() - timedelta(days=100)).timestamp()
        with patch("pathlib.Path.stat") as mock_stat:
            mock_stat.return_value.st_mtime = old_timestamp
            mock_stat.return_value.st_size = 100

            is_valid, message = validate_backup_metadata(test_file, self.logger, max_age_days=30)

            self.assertFalse(is_valid)
            self.assertIn("too old", message.lower())

    def test_validate_backup_metadata_too_small(self):
        """Test validation of backup metadata for small file."""
        test_file = self.temp_dir / "small_backup.db"
        test_file.write_text("x")  # Very small file

        is_valid, message = validate_backup_metadata(test_file, self.logger, min_size_bytes=1000)

        self.assertFalse(is_valid)
        self.assertIn("too small", message.lower())

    def test_validate_single_backup_success(self):
        """Test successful validation of single backup file."""
        db_path = self.temp_dir / "backup.db"
        self._create_test_database(db_path)

        result = validate_single_backup(db_path, self.logger)

        self.assertTrue(result["valid"])
        self.assertIn("file_hash", result)
        self.assertIn("size_bytes", result)
        self.assertIn("validation_time", result)

    def test_validate_single_backup_nonexistent(self):
        """Test validation of non-existent backup file."""
        nonexistent_path = self.temp_dir / "nonexistent.db"

        result = validate_single_backup(nonexistent_path, self.logger)

        self.assertFalse(result["valid"])
        self.assertIn("does not exist", result["error"].lower())

    def test_validate_backup_directory_success(self):
        """Test successful validation of backup directory."""
        # Create multiple backup files
        db1_path = self.temp_dir / "backup1.db"
        db2_path = self.temp_dir / "backup2.db.gz"

        self._create_test_database(db1_path)
        self._create_compressed_database(db1_path, db2_path)

        results = validate_backup_directory(self.temp_dir, self.logger)

        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["valid"] for r in results))

    def test_validate_backup_directory_empty(self):
        """Test validation of empty backup directory."""
        empty_dir = self.temp_dir / "empty"
        empty_dir.mkdir()

        results = validate_backup_directory(empty_dir, self.logger)

        self.assertEqual(len(results), 0)

    def test_validate_backup_directory_mixed_results(self):
        """Test validation of directory with both valid and invalid backups."""
        # Create valid backup
        valid_db = self.temp_dir / "valid.db"
        self._create_test_database(valid_db)

        # Create invalid backup
        invalid_db = self.temp_dir / "invalid.db"
        invalid_db.write_text("not a database")

        results = validate_backup_directory(self.temp_dir, self.logger)

        self.assertEqual(len(results), 2)
        valid_results = [r for r in results if r["valid"]]
        invalid_results = [r for r in results if not r["valid"]]

        self.assertEqual(len(valid_results), 1)
        self.assertEqual(len(invalid_results), 1)


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
        # Clean up temporary files with retry + rmtree fallback (Windows-safe)
        import shutil
        import time

        for file in self.temp_dir.rglob("*"):
            if file.is_file():
                for _ in range(10):
                    try:
                        file.unlink()
                        break
                    except PermissionError:
                        time.sleep(0.2)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

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
    @patch("validate_backup_integrity.setup_logging")
    def test_main_single_file_success(self, mock_logging, mock_argv):
        """Test main function with single valid backup file."""
        # Create test backup
        backup_file = self.temp_dir / "test_backup.db"
        self._create_test_database(backup_file)

        # Mock command line arguments
        mock_argv.__getitem__.side_effect = lambda i: [
            "validate_backup_integrity.py",
            str(backup_file),
        ][i]
        mock_argv.__len__.return_value = 2

        # Mock logger
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        # Test main function (should not raise exception)
        with patch("sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_with(0)  # Success exit code

    @patch("sys.argv")
    @patch("validate_backup_integrity.setup_logging")
    def test_main_directory_success(self, mock_logging, mock_argv):
        """Test main function with backup directory."""
        # Create test backup
        backup_file = self.temp_dir / "test_backup.db"
        self._create_test_database(backup_file)

        # Mock command line arguments for directory
        mock_argv.__getitem__.side_effect = lambda i: [
            "validate_backup_integrity.py",
            str(self.temp_dir),
        ][i]
        mock_argv.__len__.return_value = 2

        # Mock logger
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        # Test main function
        with patch("sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_with(0)  # Success exit code

    @patch("sys.argv")
    @patch("validate_backup_integrity.setup_logging")
    def test_main_with_report_output(self, mock_logging, mock_argv):
        """Test main function with JSON report output."""
        # Create test backup
        backup_file = self.temp_dir / "test_backup.db"
        self._create_test_database(backup_file)

        report_file = self.temp_dir / "report.json"

        # Mock command line arguments
        mock_argv.__getitem__.side_effect = lambda i: [
            "validate_backup_integrity.py",
            str(backup_file),
            "--report",
            str(report_file),
        ][i]
        mock_argv.__len__.return_value = 4

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

        self.assertIn("summary", report_data)
        self.assertIn("results", report_data)
        self.assertIn("timestamp", report_data)


class TestIntegrationScenarios(unittest.TestCase):
    """Integration tests for realistic backup validation scenarios."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.logger = Mock()

    def tearDown(self):
        import time

        # Clean up temporary files with retry to avoid transient locks on Windows
        for file in self.temp_dir.rglob("*"):
            if file.is_file():
                for _ in range(10):
                    try:
                        file.unlink()
                        break
                    except PermissionError:
                        time.sleep(0.2)
        # Fallback: force remove directory tree ignoring errors
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_realistic_backup_directory_validation(self):
        """Test validation of realistic backup directory structure."""
        # Create backup directory structure
        backup_dir = self.temp_dir / "backups"
        backup_dir.mkdir()

        # Create various backup files
        current_backup = backup_dir / "orch_backup_20241208_120000.db.gz"
        old_backup = backup_dir / "orch_backup_20241207_120000.db.gz"
        corrupted_backup = backup_dir / "orch_backup_20241206_120000.db.gz"

        # Create valid database
        temp_db = self.temp_dir / "temp.db"
        with sqlite3.connect(str(temp_db)) as conn:
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
            cursor.execute("INSERT INTO tasks (title, status) VALUES (?, ?)", ("Test Task", "DONE"))
            conn.commit()

        # Create compressed backups
        # NOTE: Ensure the source is read from the beginning for both outputs
        with open(temp_db, "rb") as f_in:
            with gzip.open(current_backup, "wb") as f_out:
                f_out.write(f_in.read())
            # reset file pointer for the second read
            f_in.seek(0)
            with gzip.open(old_backup, "wb") as f_out:
                f_out.write(f_in.read())

        # Create corrupted backup
        with gzip.open(corrupted_backup, "wb") as f_out:
            f_out.write(b"corrupted data")

        # Validate directory
        results = validate_backup_directory(backup_dir, self.logger)

        # Should find 3 backup files
        self.assertEqual(len(results), 3)

        # Check results
        valid_count = sum(1 for r in results if r["valid"])
        invalid_count = sum(1 for r in results if not r["valid"])

        self.assertEqual(valid_count, 2)  # current and old backups
        self.assertEqual(invalid_count, 1)  # corrupted backup

    def test_backup_validation_with_size_constraints(self):
        """Test backup validation with realistic size constraints."""
        # Create small backup (should fail size check)
        small_backup = self.temp_dir / "small.db"
        small_backup.write_text("tiny")

        # Create normal-sized backup
        normal_backup = self.temp_dir / "normal.db"
        with sqlite3.connect(str(normal_backup)) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE large_table (
                    id INTEGER PRIMARY KEY,
                    data TEXT
                )
            """
            )
            # Insert enough data to make it reasonably sized
            for i in range(100):
                cursor.execute("INSERT INTO large_table (data) VALUES (?)", (f"data_{i}" * 100,))
            conn.commit()

        # Validate with size constraints
        small_result = validate_single_backup(small_backup, self.logger, min_size_bytes=1000)
        normal_result = validate_single_backup(normal_backup, self.logger, min_size_bytes=1000)

        self.assertFalse(small_result["valid"])
        self.assertTrue(normal_result["valid"])


if __name__ == "__main__":
    unittest.main()
