# Backup and Restore Operations

## Overview

This document provides comprehensive guidance for backup and restore operations in the ORCH-Next project. The backup system includes automated scripts for validation, pruning, and restoration of database backups with full CI/CD integration.

## Quick Start

### Basic Operations

```bash
# Validate backup integrity
python scripts/ops/validate_backup_integrity.py /path/to/backups/

# Restore from latest backup
python scripts/ops/restore_backup.py /path/to/backups/ --target /path/to/database.db

# Prune old backups (dry-run)
python scripts/ops/prune_backups.py /path/to/backups/ --age-days 30 --dry-run
```

## Scripts Overview

### 1. validate_backup_integrity.py

Validates backup files for integrity, completeness, and corruption detection.

**Features:**
- SQLite database integrity checks
- Compressed file support (gzip)
- Metadata validation (size, age)
- Batch directory validation
- JSON report generation

**Usage Examples:**

```bash
# Validate single backup file
python scripts/ops/validate_backup_integrity.py backup.db.gz

# Validate entire backup directory
python scripts/ops/validate_backup_integrity.py /backups/ --report validation_report.json

# Validate with custom age threshold
python scripts/ops/validate_backup_integrity.py /backups/ --max-age-days 7

# Validate with size constraints
python scripts/ops/validate_backup_integrity.py /backups/ --min-size-mb 1 --max-size-gb 10
```

### 2. prune_backups.py

Cleans up old backup files based on retention policies.

**Features:**
- Age-based pruning
- Count-based retention
- Size-based cleanup
- Dry-run mode
- Detailed reporting

**Usage Examples:**

```bash
# Prune backups older than 30 days (dry-run)
python scripts/ops/prune_backups.py /backups/ --age-days 30 --dry-run

# Keep only latest 10 backups
python scripts/ops/prune_backups.py /backups/ --keep-count 10

# Prune to stay under 5GB total
python scripts/ops/prune_backups.py /backups/ --max-size-gb 5

# Combined policy with reporting
python scripts/ops/prune_backups.py /backups/ \
  --age-days 30 \
  --keep-count 10 \
  --max-size-gb 5 \
  --report prune_report.json
```

### 3. restore_backup.py

Restores databases from backup files with safety checks.

**Features:**
- Automatic latest backup detection
- Safety backup creation
- SQLite integrity verification
- Compressed file support
- Rollback on failure

**Usage Examples:**

```bash
# Restore from latest backup
python scripts/ops/restore_backup.py /backups/ --target database.db

# Restore specific backup file
python scripts/ops/restore_backup.py backup_20240101.db.gz --target database.db

# Dry-run restoration
python scripts/ops/restore_backup.py /backups/ --target database.db --dry-run

# Restore with verification disabled (faster)
python scripts/ops/restore_backup.py /backups/ --target database.db --no-verify

# Restore with custom safety backup location
python scripts/ops/restore_backup.py /backups/ \
  --target database.db \
  --safety-backup-dir /safety_backups/
```

## CI/CD Integration

### GitHub Actions Workflows

The backup scripts are integrated into the CI/CD pipeline through two main workflows:

#### 1. clone-gate.yml - Backup Scripts Testing

**Triggers:**
- Push/PR to any branch affecting backup scripts
- Changes to `scripts/ops/**`, `tests/ops/**`, or documentation

**Quality Gates:**
- Code linting (flake8)
- Format checking (black, isort)
- Type checking (mypy)
- Unit tests with ≥80% coverage
- Secrets scanning
- Functional validation
- Integration testing

**Coverage Requirements:**
- Unit test coverage: ≥80%
- Diff coverage: ≥80% for new/changed lines
- Integration test coverage for realistic scenarios

#### 2. compare-gate.yml - CI Consistency Review

**Purpose:**
- Ensures consistency across CI workflows
- Validates tool compatibility
- Checks for conflicts and dependencies

**Validations:**
- Virtual environment path consistency
- Secrets scan step standardization
- diff-cover tool availability
- Job dependency analysis
- Coverage configuration alignment

### Integration with Main CI Pipeline

The backup scripts are also integrated into the main `ci.yml` workflow:

```yaml
- name: Operations tests (backup scripts)
  run: python -m pytest tests/ops/ -v --cov=scripts/ops --cov-append --cov-report=xml:coverage.xml
```

This ensures backup script quality is maintained alongside the main application.

## Operational Examples

### Daily Backup Validation

```bash
#!/bin/bash
# daily_backup_check.sh

BACKUP_DIR="/var/backups/database"
REPORT_DIR="/var/log/backup_reports"
DATE=$(date +%Y%m%d)

# Validate all backups
python scripts/ops/validate_backup_integrity.py "$BACKUP_DIR" \
  --report "$REPORT_DIR/validation_$DATE.json" \
  --max-age-days 1

# Check validation results
if [ $? -eq 0 ]; then
  echo "✅ Backup validation successful"
else
  echo "❌ Backup validation failed - check $REPORT_DIR/validation_$DATE.json"
  exit 1
fi
```

### Weekly Backup Pruning

```bash
#!/bin/bash
# weekly_backup_prune.sh

BACKUP_DIR="/var/backups/database"
REPORT_DIR="/var/log/backup_reports"
DATE=$(date +%Y%m%d)

# Prune old backups
python scripts/ops/prune_backups.py "$BACKUP_DIR" \
  --age-days 30 \
  --keep-count 20 \
  --max-size-gb 50 \
  --report "$REPORT_DIR/prune_$DATE.json"

echo "Backup pruning completed - report: $REPORT_DIR/prune_$DATE.json"
```

### Emergency Restore Procedure

```bash
#!/bin/bash
# emergency_restore.sh

BACKUP_DIR="/var/backups/database"
TARGET_DB="/var/lib/app/database.db"
SAFETY_DIR="/var/backups/safety"

echo "🚨 Emergency restore procedure initiated"

# Stop application service
systemctl stop app-service

# Restore from latest backup
python scripts/ops/restore_backup.py "$BACKUP_DIR" \
  --target "$TARGET_DB" \
  --safety-backup-dir "$SAFETY_DIR" \
  --report "/tmp/emergency_restore.json"

if [ $? -eq 0 ]; then
  echo "✅ Database restored successfully"
  systemctl start app-service
  echo "✅ Application service restarted"
else
  echo "❌ Restore failed - check /tmp/emergency_restore.json"
  echo "Manual intervention required"
  exit 1
fi
```

### Automated Backup Health Monitoring

```python
#!/usr/bin/env python3
# backup_health_monitor.py

import json
import subprocess
import sys
from datetime import datetime, timedelta

def check_backup_health():
    """Monitor backup health and alert on issues."""
    
    backup_dir = "/var/backups/database"
    max_age_hours = 25  # Daily backups should be < 25 hours old
    
    # Run validation
    result = subprocess.run([
        "python", "scripts/ops/validate_backup_integrity.py",
        backup_dir,
        "--report", "/tmp/health_check.json",
        f"--max-age-hours", str(max_age_hours)
    ], capture_output=True, text=True)
    
    # Parse results
    with open("/tmp/health_check.json") as f:
        report = json.load(f)
    
    # Check for issues
    issues = []
    if not report["summary"]["all_valid"]:
        issues.append("Invalid backups detected")
    
    if report["summary"]["total_files"] == 0:
        issues.append("No backup files found")
    
    # Alert if issues found
    if issues:
        print(f"🚨 Backup health issues: {', '.join(issues)}")
        # Send alert (email, Slack, etc.)
        return False
    else:
        print("✅ Backup health check passed")
        return True

if __name__ == "__main__":
    success = check_backup_health()
    sys.exit(0 if success else 1)
```

## Configuration

### Environment Variables

```bash
# Backup script configuration
export BACKUP_DEFAULT_PATTERN="*.db*"
export BACKUP_MAX_AGE_DAYS=30
export BACKUP_MIN_SIZE_MB=1
export BACKUP_MAX_SIZE_GB=10

# Logging configuration
export BACKUP_LOG_LEVEL=INFO
export BACKUP_LOG_FORMAT="%(asctime)s - %(levelname)s - %(message)s"

# Safety settings
export BACKUP_SAFETY_CHECKS=true
export BACKUP_VERIFY_RESTORE=true
```

### Configuration Files

Create `config/backup_config.json`:

```json
{
  "validation": {
    "max_age_days": 30,
    "min_size_mb": 1,
    "max_size_gb": 10,
    "file_patterns": ["*.db", "*.db.gz", "*.sqlite", "*.sqlite.gz"]
  },
  "pruning": {
    "default_age_days": 30,
    "default_keep_count": 20,
    "default_max_size_gb": 50
  },
  "restoration": {
    "verify_integrity": true,
    "create_safety_backup": true,
    "safety_backup_suffix": ".safety"
  },
  "logging": {
    "level": "INFO",
    "format": "%(asctime)s - %(levelname)s - %(message)s"
  }
}
```

## Frequently Asked Questions (FAQ)

### Q: How do I validate a specific backup file?

**A:** Use the validation script with the file path:

```bash
python scripts/ops/validate_backup_integrity.py /path/to/backup.db.gz
```

### Q: What happens if a restore fails?

**A:** The restore script creates a safety backup before restoration. If the restore fails or verification fails, the original database is automatically restored from the safety backup.

### Q: How do I test backup scripts without affecting production data?

**A:** Use the `--dry-run` flag available in all scripts:

```bash
python scripts/ops/restore_backup.py /backups/ --target test.db --dry-run
python scripts/ops/prune_backups.py /backups/ --age-days 30 --dry-run
```

### Q: Can I customize the backup file patterns?

**A:** Yes, use the `--pattern` option:

```bash
python scripts/ops/validate_backup_integrity.py /backups/ --pattern "*.sqlite.gz"
```

### Q: How do I monitor backup script performance?

**A:** All scripts generate detailed JSON reports with timing information:

```bash
python scripts/ops/validate_backup_integrity.py /backups/ --report report.json
cat report.json | jq '.performance'
```

### Q: What's the recommended backup retention policy?

**A:** A typical policy might be:
- Keep daily backups for 30 days
- Keep weekly backups for 12 weeks
- Keep monthly backups for 12 months
- Limit total backup size to reasonable storage constraints

```bash
# Daily cleanup
python scripts/ops/prune_backups.py /backups/daily/ --age-days 30

# Weekly cleanup
python scripts/ops/prune_backups.py /backups/weekly/ --age-days 84

# Monthly cleanup
python scripts/ops/prune_backups.py /backups/monthly/ --age-days 365
```

### Q: How do I integrate backup validation into monitoring systems?

**A:** Use the JSON report output and exit codes:

```bash
# Check exit code
python scripts/ops/validate_backup_integrity.py /backups/
if [ $? -ne 0 ]; then
  # Send alert
  curl -X POST "https://monitoring.example.com/alert" \
    -d "message=Backup validation failed"
fi

# Parse JSON report
python scripts/ops/validate_backup_integrity.py /backups/ --report report.json
jq '.summary.all_valid' report.json  # Returns true/false
```

### Q: Can I run backup operations in parallel?

**A:** Yes, but be careful with concurrent operations on the same files:

```bash
# Safe: Validate different directories in parallel
python scripts/ops/validate_backup_integrity.py /backups/dir1/ &
python scripts/ops/validate_backup_integrity.py /backups/dir2/ &
wait

# Unsafe: Don't prune and restore simultaneously
# python scripts/ops/prune_backups.py /backups/ &  # DON'T DO THIS
# python scripts/ops/restore_backup.py /backups/ --target db.db &
```

### Q: How do I handle compressed backups?

**A:** All scripts automatically detect and handle gzip-compressed files:

```bash
# Works with both compressed and uncompressed files
python scripts/ops/validate_backup_integrity.py backup.db      # Uncompressed
python scripts/ops/validate_backup_integrity.py backup.db.gz  # Compressed
```

### Q: What should I do if backup validation fails?

**A:** 1. Check the detailed report for specific issues
2. Verify backup file permissions and accessibility
3. Check for disk space issues
4. Validate the backup creation process
5. Consider restoring from an earlier known-good backup

```bash
# Get detailed failure information
python scripts/ops/validate_backup_integrity.py /backups/ --report detailed_report.json
jq '.files[] | select(.valid == false)' detailed_report.json
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Fix file permissions
   chmod 644 /path/to/backup.db.gz
   chmod 755 /path/to/backup/directory/
   ```

2. **Corrupted Backup Files**
   ```bash
   # Check file integrity
   gzip -t backup.db.gz
   # If corrupted, restore from earlier backup
   ```

3. **Insufficient Disk Space**
   ```bash
   # Check available space
   df -h /path/to/backups/
   # Prune old backups to free space
   python scripts/ops/prune_backups.py /backups/ --max-size-gb 10
   ```

4. **SQLite Database Locked**
   ```bash
   # Check for active connections
   lsof /path/to/database.db
   # Stop application before restore
   systemctl stop app-service
   ```

## Security Considerations

- Backup files may contain sensitive data - ensure proper access controls
- Use encrypted storage for backup repositories
- Regularly rotate backup encryption keys
- Audit backup access logs
- Validate backup integrity before restoration
- Test restore procedures regularly in isolated environments

## Performance Optimization

- Use compression for large databases (`gzip`)
- Implement incremental backup strategies for large datasets
- Schedule backup operations during low-traffic periods
- Use SSD storage for backup repositories when possible
- Monitor backup operation performance and adjust retention policies

## Related Documentation

- [Operations Manual](operations.md) - Detailed backup/restore functions
- [CI/CD Workflows](.github/workflows/) - Automated testing and validation
- [Security Guidelines](security.md) - Backup security best practices
- [Monitoring Setup](monitoring.md) - Backup health monitoring configuration