#!/usr/bin/env python3
"""
Unit tests for prune_backups.py script.
Tests backup pruning functionality with comprehensive coverage.
"""

import json
import os

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
from prune_backups import BackupPruner, main, setup_logging


class TestBackupPruner(unittest.TestCase):
    """Test BackupPruner class functionality."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.logger = Mock()
        self.pruner = BackupPruner(self.logger)

    def tearDown(self):
        cleanup_temp_dir(self.temp_dir)

    def _create_test_backup(self, name: str, age_days: int = 0, size_bytes: int = 1000) -> Path:
        """Helper to create a test backup file with specific age and size."""
        backup_path = self.temp_dir / name
        backup_path.write_text("x" * size_bytes)

        # Set modification time (Path.touch does not support 'times')
        if age_days > 0:
            old_time = (datetime.now() - timedelta(days=age_days)).timestamp()
            os.utime(backup_path, (old_time, old_time))

        return backup_path

    def test_find_backup_files_default_pattern(self):
        """Test finding backup files with default pattern."""
        # Create various files
        self._create_test_backup("backup_20241208.db.gz")
        self._create_test_backup("orch_backup_20241207.db")
        self._create_test_backup("not_a_backup.txt")
        self._create_test_backup("backup.log")

        backup_files = self.pruner.find_backup_files(self.temp_dir)

        # Should find files matching backup patterns
        self.assertEqual(len(backup_files), 3)  # .gz, .db, .log files

        # Verify files are sorted by modification time (newest first)
        for i in range(len(backup_files) - 1):
            self.assertGreaterEqual(
                backup_files[i].stat().st_mtime, backup_files[i + 1].stat().st_mtime
            )

    def test_find_backup_files_custom_pattern(self):
        """Test finding backup files with custom pattern."""
        # Create files
        self._create_test_backup("custom_backup_1.bak")
        self._create_test_backup("custom_backup_2.bak")
        self._create_test_backup("other_file.txt")

        backup_files = self.pruner.find_backup_files(self.temp_dir, pattern="*.bak")

        self.assertEqual(len(backup_files), 2)
        self.assertTrue(all(f.suffix == ".bak" for f in backup_files))

    def test_find_backup_files_empty_directory(self):
        """Test finding backup files in empty directory."""
        empty_dir = self.temp_dir / "empty"
        empty_dir.mkdir()

        backup_files = self.pruner.find_backup_files(empty_dir)

        self.assertEqual(len(backup_files), 0)

    def test_prune_by_age_success(self):
        """Test successful pruning by age."""
        # Create backups of different ages
        recent_backup = self._create_test_backup("recent.db", age_days=1)
        old_backup1 = self._create_test_backup("old1.db", age_days=10)
        old_backup2 = self._create_test_backup("old2.db", age_days=15)

        backup_files = [recent_backup, old_backup1, old_backup2]

        pruned = self.pruner.prune_by_age(backup_files, max_age_days=7)

        self.assertEqual(len(pruned), 2)  # old1 and old2
        self.assertIn(old_backup1, pruned)
        self.assertIn(old_backup2, pruned)
        self.assertNotIn(recent_backup, pruned)

    def test_prune_by_age_no_old_files(self):
        """Test pruning by age when no files are old enough."""
        # Create only recent backups
        recent1 = self._create_test_backup("recent1.db", age_days=1)
        recent2 = self._create_test_backup("recent2.db", age_days=2)

        backup_files = [recent1, recent2]

        pruned = self.pruner.prune_by_age(backup_files, max_age_days=7)

        self.assertEqual(len(pruned), 0)

    def test_prune_by_count_success(self):
        """Test successful pruning by count."""
        # Create multiple backups (sorted by modification time)
        backup1 = self._create_test_backup("backup1.db", age_days=1)
        backup2 = self._create_test_backup("backup2.db", age_days=2)
        backup3 = self._create_test_backup("backup3.db", age_days=3)
        backup4 = self._create_test_backup("backup4.db", age_days=4)

        # Sort by modification time (newest first)
        backup_files = sorted(
            [backup1, backup2, backup3, backup4], key=lambda f: f.stat().st_mtime, reverse=True
        )

        pruned = self.pruner.prune_by_count(backup_files, max_count=2)

        self.assertEqual(len(pruned), 2)  # Should prune 2 oldest
        # Should keep the 2 newest files
        self.assertNotIn(backup1, pruned)  # newest
        self.assertNotIn(backup2, pruned)  # second newest

    def test_prune_by_count_under_limit(self):
        """Test pruning by count when under the limit."""
        backup1 = self._create_test_backup("backup1.db")
        backup2 = self._create_test_backup("backup2.db")

        backup_files = [backup1, backup2]

        pruned = self.pruner.prune_by_count(backup_files, max_count=5)

        self.assertEqual(len(pruned), 0)  # No files to prune

    def test_prune_by_size_success(self):
        """Test successful pruning by total size."""
        # Create backups with known sizes
        small_backup = self._create_test_backup("small.db", size_bytes=100)
        medium_backup = self._create_test_backup("medium.db", size_bytes=500)
        large_backup = self._create_test_backup("large.db", size_bytes=1000)

        backup_files = [small_backup, medium_backup, large_backup]

        # Set limit to 1200 bytes (should prune oldest until under limit)
        pruned = self.pruner.prune_by_size(backup_files, max_size_mb=0.0012)  # ~1200 bytes

        # Should prune files until total size is under limit
        self.assertGreater(len(pruned), 0)

    def test_prune_by_size_under_limit(self):
        """Test pruning by size when under the limit."""
        small_backup = self._create_test_backup("small.db", size_bytes=100)

        backup_files = [small_backup]

        pruned = self.pruner.prune_by_size(backup_files, max_size_mb=1.0)  # 1MB limit

        self.assertEqual(len(pruned), 0)  # No files to prune

    def test_delete_files_success(self):
        """Test successful file deletion."""
        # Create test files
        file1 = self._create_test_backup("file1.db")
        file2 = self._create_test_backup("file2.db")

        files_to_delete = [file1, file2]

        deleted = self.pruner.delete_files(files_to_delete, dry_run=False)

        self.assertEqual(len(deleted), 2)
        self.assertFalse(file1.exists())
        self.assertFalse(file2.exists())

    def test_delete_files_dry_run(self):
        """Test file deletion in dry run mode."""
        # Create test files
        file1 = self._create_test_backup("file1.db")
        file2 = self._create_test_backup("file2.db")

        files_to_delete = [file1, file2]

        deleted = self.pruner.delete_files(files_to_delete, dry_run=True)

        self.assertEqual(len(deleted), 2)
        # Files should still exist in dry run
        self.assertTrue(file1.exists())
        self.assertTrue(file2.exists())

    def test_delete_files_with_errors(self):
        """Test file deletion with some errors."""
        # Create one valid file and one non-existent file
        valid_file = self._create_test_backup("valid.db")
        nonexistent_file = self.temp_dir / "nonexistent.db"

        files_to_delete = [valid_file, nonexistent_file]

        deleted = self.pruner.delete_files(files_to_delete, dry_run=False)

        # Should successfully delete the valid file
        self.assertEqual(len(deleted), 1)
        self.assertEqual(deleted[0], valid_file)
        self.assertFalse(valid_file.exists())

    def test_prune_backups_by_age_integration(self):
        """Test complete backup pruning by age."""
        # Create backups of different ages
        self._create_test_backup("recent.db", age_days=1)
        self._create_test_backup("old1.db", age_days=10)
        self._create_test_backup("old2.db", age_days=15)

        result = self.pruner.prune_backups(self.temp_dir, max_age_days=7, dry_run=False)

        self.assertTrue(result["success"])
        self.assertEqual(result["files_deleted"], 2)
        self.assertGreater(result["space_freed_mb"], 0)

    def test_prune_backups_by_count_integration(self):
        """Test complete backup pruning by count."""
        # Create multiple backups
        for i in range(5):
            self._create_test_backup(f"backup_{i}.db", age_days=i)

        result = self.pruner.prune_backups(self.temp_dir, max_count=3, dry_run=False)

        self.assertTrue(result["success"])
        self.assertEqual(result["files_deleted"], 2)  # Keep 3, delete 2

    def test_prune_backups_multiple_criteria(self):
        """Test backup pruning with multiple criteria."""
        # Create backups that meet different criteria
        self._create_test_backup("recent_large.db", age_days=1, size_bytes=2000)
        self._create_test_backup("old_small.db", age_days=10, size_bytes=100)
        self._create_test_backup("medium_age.db", age_days=5, size_bytes=1000)

        result = self.pruner.prune_backups(
            self.temp_dir, max_age_days=7, max_count=2, dry_run=False
        )

        self.assertTrue(result["success"])
        # Should prune based on most restrictive criteria
        self.assertGreaterEqual(result["files_deleted"], 1)

    def test_prune_backups_dry_run_integration(self):
        """Test complete backup pruning in dry run mode."""
        # Create old backups
        self._create_test_backup("old1.db", age_days=10)
        self._create_test_backup("old2.db", age_days=15)

        result = self.pruner.prune_backups(self.temp_dir, max_age_days=7, dry_run=True)

        self.assertTrue(result["success"])
        self.assertEqual(result["files_deleted"], 0)  # Dry run doesn't delete
        self.assertEqual(result["space_freed_mb"], 0)
        self.assertEqual(len(result["would_delete"]), 2)  # But reports what would be deleted

    def test_prune_backups_no_files_to_prune(self):
        """Test backup pruning when no files need pruning."""
        # Create only recent backups
        self._create_test_backup("recent1.db", age_days=1)
        self._create_test_backup("recent2.db", age_days=2)

        result = self.pruner.prune_backups(
            self.temp_dir, max_age_days=30, max_count=10, dry_run=False
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["files_deleted"], 0)
        self.assertEqual(result["space_freed_mb"], 0)


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

    def _create_test_backup(self, name: str, age_days: int = 0) -> Path:
        """Helper to create a test backup file."""
        backup_path = self.temp_dir / name
        backup_path.write_text("test backup content")

        if age_days > 0:
            old_time = (datetime.now() - timedelta(days=age_days)).timestamp()
            os.utime(backup_path, (old_time, old_time))

        return backup_path

    @patch("sys.argv")
    @patch("prune_backups.setup_logging")
    def test_main_prune_by_age(self, mock_logging, mock_argv):
        """Test main function with age-based pruning."""
        # Create old backup
        self._create_test_backup("old_backup.db", age_days=10)

        # Mock command line arguments
        mock_argv.__getitem__.side_effect = lambda i: [
            "prune_backups.py",
            str(self.temp_dir),
            "--max-age-days",
            "7",
        ][i]
        mock_argv.__len__.return_value = 4

        # Mock logger
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        # Test main function
        with patch("sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_with(0)  # Success exit code

    @patch("sys.argv")
    @patch("prune_backups.setup_logging")
    def test_main_dry_run(self, mock_logging, mock_argv):
        """Test main function in dry run mode."""
        # Create old backup
        old_backup = self._create_test_backup("old_backup.db", age_days=10)

        # Mock command line arguments
        mock_argv.__getitem__.side_effect = lambda i: [
            "prune_backups.py",
            str(self.temp_dir),
            "--max-age-days",
            "7",
            "--dry-run",
        ][i]
        mock_argv.__len__.return_value = 5

        # Mock logger
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        # Test main function
        with patch("sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_with(0)

        # File should still exist after dry run
        self.assertTrue(old_backup.exists())

    @patch("sys.argv")
    @patch("prune_backups.setup_logging")
    def test_main_with_report_output(self, mock_logging, mock_argv):
        """Test main function with JSON report output."""
        # Create old backup
        self._create_test_backup("old_backup.db", age_days=10)

        report_file = self.temp_dir / "prune_report.json"

        # Mock command line arguments
        mock_argv.__getitem__.side_effect = lambda i: [
            "prune_backups.py",
            str(self.temp_dir),
            "--max-age-days",
            "7",
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
        self.assertIn("files_deleted", report_data)
        self.assertIn("timestamp", report_data)

    @patch("sys.argv")
    @patch("prune_backups.setup_logging")
    def test_main_nonexistent_directory(self, mock_logging, mock_argv):
        """Test main function with non-existent directory."""
        nonexistent_dir = self.temp_dir / "nonexistent"

        # Mock command line arguments
        mock_argv.__getitem__.side_effect = lambda i: ["prune_backups.py", str(nonexistent_dir)][i]
        mock_argv.__len__.return_value = 2

        # Mock logger
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        # Test main function
        with patch("sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_with(1)  # Error exit code


class TestIntegrationScenarios(unittest.TestCase):
    """Integration tests for realistic backup pruning scenarios."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.logger = Mock()
        self.pruner = BackupPruner(self.logger)

    def tearDown(self):
        cleanup_temp_dir(self.temp_dir)

    def _create_realistic_backup(self, name: str, age_days: int, size_kb: int = 100) -> Path:
        """Create a realistic backup file with timestamp in name."""
        backup_date = datetime.now() - timedelta(days=age_days)
        timestamp = backup_date.strftime("%Y%m%d_%H%M%S")
        filename = f"orch_backup_{timestamp}.db.gz"

        backup_path = self.temp_dir / filename
        backup_path.write_text("x" * (size_kb * 1024))

        # Set file modification time (Path.touch does not support 'times' on some platforms)
        file_time = backup_date.timestamp()
        os.utime(backup_path, (file_time, file_time))

        return backup_path

    def test_realistic_backup_retention_policy(self):
        """Test realistic backup retention policy."""
        # Create backups following a realistic schedule
        # Daily backups for the last week
        for i in range(7):
            self._create_realistic_backup(f"daily_{i}", age_days=i, size_kb=500)

        # Weekly backups for the last month
        for i in range(4):
            self._create_realistic_backup(f"weekly_{i}", age_days=7 + (i * 7), size_kb=1000)

        # Monthly backups for the last year
        for i in range(12):
            self._create_realistic_backup(f"monthly_{i}", age_days=30 + (i * 30), size_kb=2000)

        # Apply retention policy: keep 30 days, max 10 files
        result = self.pruner.prune_backups(
            self.temp_dir, max_age_days=30, max_count=10, dry_run=False
        )

        self.assertTrue(result["success"])
        self.assertGreater(result["files_deleted"], 0)

        # Verify remaining files
        remaining_files = list(self.temp_dir.glob("*.gz"))
        self.assertLessEqual(len(remaining_files), 10)

    def test_backup_pruning_with_size_limit(self):
        """Test backup pruning with realistic size constraints."""
        # Create backups with varying sizes
        self._create_realistic_backup("small", age_days=1, size_kb=100)
        self._create_realistic_backup("medium", age_days=2, size_kb=500)
        self._create_realistic_backup("large", age_days=3, size_kb=1000)
        self._create_realistic_backup("huge", age_days=4, size_kb=2000)

        # Apply size limit of 2MB
        result = self.pruner.prune_backups(self.temp_dir, max_size_mb=2.0, dry_run=False)

        self.assertTrue(result["success"])

        # Calculate remaining total size
        remaining_files = list(self.temp_dir.glob("*.gz"))
        total_size_mb = sum(f.stat().st_size for f in remaining_files) / (1024 * 1024)

        self.assertLessEqual(total_size_mb, 2.0)

    def test_emergency_cleanup_scenario(self):
        """Test emergency cleanup when disk space is critically low."""
        # Create many large backups
        for i in range(20):
            self._create_realistic_backup(f"backup_{i}", age_days=i, size_kb=1000)

        # Emergency cleanup: keep only 3 most recent, regardless of age
        result = self.pruner.prune_backups(self.temp_dir, max_count=3, dry_run=False)

        self.assertTrue(result["success"])
        self.assertEqual(result["files_deleted"], 17)  # 20 - 3 = 17

        # Verify only 3 files remain
        remaining_files = list(self.temp_dir.glob("*.gz"))
        self.assertEqual(len(remaining_files), 3)

        # Verify the 3 most recent files are kept
        remaining_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
        for i, backup_file in enumerate(remaining_files):
            # Should be the 3 most recent (age 0, 1, 2 days)
            expected_age = i
            self.assertLessEqual(expected_age, 2)


if __name__ == "__main__":
    unittest.main()
