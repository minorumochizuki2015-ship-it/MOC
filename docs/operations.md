# ORCH-Next Operations Guide

## Overview

This guide provides comprehensive operational procedures for deploying, monitoring, and maintaining the ORCH-Next orchestration system. It covers installation, configuration, monitoring, troubleshooting, and best practices for production environments.

## System Requirements

### Minimum Requirements
- **OS**: Windows 10/11, Windows Server 2019+, or Linux (Ubuntu 20.04+)
- **Python**: 3.11 or higher
- **Memory**: 4GB RAM
- **Storage**: 10GB available space
- **Network**: HTTP/HTTPS access for API endpoints

### Recommended Production Requirements
- **OS**: Windows Server 2022 or Ubuntu 22.04 LTS
- **Python**: 3.11 or 3.12
- **Memory**: 8GB RAM
- **Storage**: 50GB SSD storage
- **CPU**: 4+ cores
- **Network**: Dedicated network interface, load balancer support

### Dependencies
- SQLite 3.35+ (included with Python)
- FastAPI and dependencies (see requirements.txt)
- Optional: PostgreSQL 13+ for production database
- Optional: Redis 6+ for distributed caching

## Installation

### Development Installation

1. **Clone Repository**:
```bash
git clone https://github.com/your-org/orch-next.git
cd orch-next
```

2. **Create Virtual Environment**:
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/Mac
source .venv/bin/activate
```

3. **Install Dependencies**:
```bash
pip install -r requirements.txt
```

4. **Initialize Database**:
```bash
python -m src.dispatcher --init-db
```

5. **Create Initial User**:
```bash
python -m src.security --create-admin-user
```

6. **Start Development Server**:
```bash
uvicorn src.orchestrator:app --reload --host 0.0.0.0 --port 8000
```

### Production Installation

#### Using systemd (Linux)

1. **Create Service User**:
```bash
sudo useradd --system --shell /bin/false --home /opt/orch-next orch-next
```

2. **Install Application**:
```bash
sudo mkdir -p /opt/orch-next
sudo chown orch-next:orch-next /opt/orch-next
sudo -u orch-next git clone https://github.com/your-org/orch-next.git /opt/orch-next
cd /opt/orch-next
sudo -u orch-next python -m venv .venv
sudo -u orch-next .venv/bin/pip install -r requirements.txt
```

3. **Create Configuration**:
```bash
sudo mkdir -p /etc/orch-next
sudo cp config/production.yaml.example /etc/orch-next/config.yaml
sudo chown orch-next:orch-next /etc/orch-next/config.yaml
sudo chmod 600 /etc/orch-next/config.yaml
```

4. **Create systemd Service**:
```ini
# /etc/systemd/system/orch-next.service
[Unit]
Description=ORCH-Next Orchestration Service
After=network.target
Wants=network.target

[Service]
Type=exec
User=orch-next
Group=orch-next
WorkingDirectory=/opt/orch-next
Environment=PATH=/opt/orch-next/.venv/bin
Environment=ORCH_CONFIG_PATH=/etc/orch-next/config.yaml
ExecStart=/opt/orch-next/.venv/bin/uvicorn src.orchestrator:app --host 0.0.0.0 --port 8000 --workers 4
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

5. **Enable and Start Service**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable orch-next
sudo systemctl start orch-next
```

#### Using Windows Service

1. **Install as Windows Service**:
```powershell
# Install NSSM (Non-Sucking Service Manager)
choco install nssm

# Create service
nssm install ORCH-Next "C:\ORCH-Next\.venv\Scripts\python.exe"
nssm set ORCH-Next Arguments "-m uvicorn src.orchestrator:app --host 0.0.0.0 --port 8000"
nssm set ORCH-Next AppDirectory "C:\ORCH-Next"
nssm set ORCH-Next DisplayName "ORCH-Next Orchestration Service"
nssm set ORCH-Next Description "Python-based orchestration and task management system"
nssm set ORCH-Next Start SERVICE_AUTO_START

# Start service
nssm start ORCH-Next
```

##### Windows Dashboard Service (Waitress/NSSM) — default port 5001
本番ダッシュボードは Waitress + NSSM により `127.0.0.1:5001` で常駐します。インストールは以下のスクリプトを利用します。

```powershell
pwsh scripts/ops/nssm_install_5001.ps1 -Apply
```

設定の要点:
- AppDirectory: リポジトリルート（例: `C:\Users\User\Trae\ORCH-Next`）
- AppEnvironmentExtra: `ORCH_HOST=127.0.0.1;ORCH_PORT=5001;ORCH_MCP_TOKEN=<managed in NSSM env>`
- Start: `SERVICE_AUTO_START`
- ログ: `data\logs\current\service_stdout.log` / `service_stderr.log`（ローテーション: Files=5, Bytes=10MB, Seconds=86400）

ヘルスエンドポイント（例）:
- `GET http://127.0.0.1:5001/healthz`
- `OPTIONS http://127.0.0.1:5001/preview`（プリフライト: `Access-Control-Max-Age: 600`, `Vary: Origin`）
- `GET http://127.0.0.1:5001/mcp/ping`（未認証は 401, `Server: waitress`）
- `GET http://127.0.0.1:5001/events/health`（SSE: `Content-Type: text/event-stream`, `Cache-Control: no-cache`）

## Configuration

### Logging Policy and Usage

- 共通ロガー取得は `app.shared.logging_config.get_logger` を使用します。pytest 実行時は自動的に FileHandler が抑止され、stderr への StreamHandler のみ有効になります（通常運用は INFO、pytest は WARNING。`LOG_LEVEL` または `ORCH_LOG_LEVEL` 環境変数で上書き可能）。
- 互換ヘルパー `_in_pytest` を提供しています。

使用例:
```python
from app.shared.logging_config import get_logger, _in_pytest
logger = get_logger(__name__, in_pytest=_in_pytest())
logger.info("operation started", extra={"operation": "dispatch"})
```

環境変数例:
```env
LOG_LEVEL=DEBUG  # または ORCH_LOG_LEVEL=DEBUG
```

テストでのログノイズ抑止:
```python
def test_dispatch(caplog):
    caplog.set_level("WARNING")
    # ...
```


### Configuration File Structure

```yaml
# config/production.yaml
database:
  path: "data/orch.db"
  pool_size: 10
  timeout: 30
  backup_interval: 3600  # 1 hour

security:
  jwt_secret: "${JWT_SECRET}"
  jwt_expiry: 3600  # 1 hour
  webhook_secret: "${WEBHOOK_SECRET}"
  rate_limit:
    requests_per_minute: 100
    burst_size: 20
  password_policy:
    min_length: 12
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_symbols: true

monitoring:
  interval: 60  # seconds
  metrics_retention: 2592000  # 30 days
  alert_thresholds:
    cpu_percent: 80
    memory_percent: 85
    disk_usage_percent: 90
    response_time_ms: 2000
    error_rate_percent: 5
  
  # Self-healing configuration
  self_healing:
    enabled: true
    max_retries: 3
    backoff_multiplier: 2
    actions:
      - restart
      - isolate
      - rollback

notifications:
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#orch-alerts"
    username: "ORCH-Next"
  mention_on_critical: true
  
## CI プリフライトとヘルスチェック

運用前の早期検知と安定性向上のため、CI に以下のプリフライトを導入しています。

1. Kernel healthcheck の実行
   - `kernel.healthcheck()` を CI（Windows ジョブ）開始直後に実行し、`status=="ok"` 以外は失敗扱いにします。
   - 実行例：
     ```powershell
     python -c "import importlib, sys; mod=importlib.import_module('kernel'); s=mod.healthcheck().get('status'); print(f'kernel health: {s}'); sys.exit(0 if s=='ok' else 1)"
     ```

2. 差分カバレッジの品質ゲート
   - `diff-cover coverage.xml --compare-branch origin/main --fail-under=80` を実行し、必要十分なテストが新規差分に対して伴っていることを検証します。

3. ディレクトリ準備（Windows）
   - 次のディレクトリを事前作成：
     - `data/`
     - `data/baseline/`
     - `data/baseline/milestones/`
     - `data/baseline/tasks/`
     - `data/baseline/metrics/`

上記は GitHub Actions の `test` ジョブに組み込まれており、詳細は `.github/workflows/ci.yml` を参照してください。

  email:
    smtp_server: "${SMTP_SERVER}"
    smtp_port: 587
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"
    from_address: "orch@company.com"
    to_addresses:
      - "ops-team@company.com"
      - "platform-team@company.com"

logging:
  level: "INFO"
  format: "json"
  file: "logs/orch-next.log"
  max_size: "100MB"
  backup_count: 10
  
  # Log specific modules
  loggers:
    "src.orchestrator": "INFO"
    "src.dispatcher": "INFO"
    "src.security": "WARNING"
    "src.monitor": "INFO"
    "uvicorn": "WARNING"

features:
  enable_sse: true
  enable_webhooks: true
  enable_monitoring: true
  enable_self_healing: true
  max_concurrent_tasks: 100
  task_timeout_default: 300
```

### Environment Variables

Create a `.env` file for sensitive configuration:

```bash
# Security
JWT_SECRET=your-super-secret-jwt-key-here
WEBHOOK_SECRET=your-webhook-secret-key-here

# Database (if using PostgreSQL)
DATABASE_URL=postgresql://user:password@localhost:5432/orch_next

# Monitoring
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# Email notifications
SMTP_SERVER=smtp.company.com
SMTP_USERNAME=orch@company.com
SMTP_PASSWORD=your-smtp-password

# External integrations
GRAFANA_API_KEY=your-grafana-api-key
PROMETHEUS_URL=http://localhost:9090

# Feature flags
ENABLE_DEBUG_MODE=false
ENABLE_PROFILING=false
MAINTENANCE_MODE=false
```

### Configuration Validation

```bash
# Validate configuration
python -m src.config --validate

# Test database connection
python -m src.dispatcher --test-db

# Test security configuration
python -m src.security --test-config

# Test monitoring setup
python -m src.monitor --test-config
```

## Monitoring and Observability

### Metrics Collection

#### Prometheus Integration

1. **Configure Prometheus** (`prometheus.yml`):
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'orch-next'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

2. **Key Metrics to Monitor**:
```
# HTTP Metrics
orch_http_requests_total{method, status, endpoint}
orch_http_request_duration_seconds{method, endpoint}

# Task Metrics
orch_task_duration_seconds{core_id, status}
orch_tasks_total{core_id, status}
orch_task_queue_depth{priority}

# System Metrics
orch_system_cpu_percent
orch_system_memory_percent
orch_system_disk_usage_bytes{path}

# Lock Metrics
orch_locks_active{resource_type}
orch_lock_wait_duration_seconds{resource_type}

# SSE Metrics
orch_sse_connections_active
orch_sse_messages_sent_total
```

#### Grafana Dashboard

Import the provided Grafana dashboard (`monitoring/grafana-dashboard.json`):

```json
{
  "dashboard": {
    "title": "ORCH-Next Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(orch_http_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Task Queue Depth",
        "type": "graph",
        "targets": [
          {
            "expr": "orch_task_queue_depth",
            "legendFormat": "Priority {{priority}}"
          }
        ]
      },
      {
        "title": "System Resources",
        "type": "graph",
        "targets": [
          {
            "expr": "orch_system_cpu_percent",
            "legendFormat": "CPU %"
          },
          {
            "expr": "orch_system_memory_percent",
            "legendFormat": "Memory %"
          }
        ]
      }
    ]
  }
}
```

### Logging

#### Log Configuration

```python
# logging_config.py
import logging.config

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "class": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s"
        },
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "standard",
            "stream": "ext://sys.stdout"
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "INFO",
            "formatter": "json",
            "filename": "logs/orch-next.log",
            "maxBytes": 104857600,  # 100MB
            "backupCount": 10
        }
    },
    "loggers": {
        "src": {
            "level": "INFO",
            "handlers": ["console", "file"],
            "propagate": False
        },
        "uvicorn": {
            "level": "WARNING",
            "handlers": ["console", "file"],
            "propagate": False
        }
    },
    "root": {
        "level": "INFO",
        "handlers": ["console", "file"]
    }
}
```

#### Log Analysis

```bash
# View recent logs
tail -f logs/orch-next.log

# Search for errors
grep -i error logs/orch-next.log

# Analyze request patterns
jq '.message | select(contains("HTTP"))' logs/orch-next.log

# Monitor task completion rates
jq 'select(.event_type == "task.completed") | .data.duration' logs/orch-next.log | \
  awk '{sum+=$1; count++} END {print "Average duration:", sum/count}'
```

### Health Checks

#### Application Health Check

```bash
# Basic health check
curl -f http://localhost:8000/health

# Detailed health check with authentication
curl -H "Authorization: Bearer $JWT_TOKEN" \
     http://localhost:8000/health?detailed=true
```

#### Database Health Check

```python
# scripts/health_check.py
import sqlite3
import sys
from pathlib import Path

def check_database_health():
    db_path = Path("data/orch.db")
    
    if not db_path.exists():
        print("ERROR: Database file not found")
        return False
    
    try:
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
            
            # Check table integrity
            cursor.execute("PRAGMA integrity_check")
            result = cursor.fetchone()[0]
            
            if result != "ok":
                print(f"ERROR: Database integrity check failed: {result}")
                return False
            
            # Check recent activity
            cursor.execute("""
                SELECT COUNT(*) FROM tasks 
                WHERE created_at > datetime('now', '-1 hour')
            """)
            recent_tasks = cursor.fetchone()[0]
            
            print(f"Database healthy - {recent_tasks} tasks in last hour")
            return True
            
    except Exception as e:
        print(f"ERROR: Database check failed: {e}")
        return False

if __name__ == "__main__":
    if not check_database_health():
        sys.exit(1)
```

## Backup and Recovery

### Database Backup

#### Automated Backup Script

```python
# scripts/backup_database.py
import sqlite3
import shutil
import gzip
from datetime import datetime
from pathlib import Path

def backup_database():
    """Create compressed backup of SQLite database"""
    
    source_db = Path("data/orch.db")
    backup_dir = Path("data/backups")
    backup_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"orch_backup_{timestamp}.db"
    compressed_file = backup_dir / f"orch_backup_{timestamp}.db.gz"
    
    try:
        # Create backup using SQLite backup API
        with sqlite3.connect(str(source_db)) as source:
            with sqlite3.connect(str(backup_file)) as backup:
                source.backup(backup)
        
        # Compress backup
        with open(backup_file, 'rb') as f_in:
            with gzip.open(compressed_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        # Remove uncompressed backup
        backup_file.unlink()
        
        print(f"Backup created: {compressed_file}")
        
        # Cleanup old backups (keep last 30 days)
        cleanup_old_backups(backup_dir, days=30)
        
    except Exception as e:
        print(f"Backup failed: {e}")
        raise

def cleanup_old_backups(backup_dir: Path, days: int = 30):
    """Remove backups older than specified days"""
    cutoff = datetime.now().timestamp() - (days * 24 * 3600)
    
    for backup_file in backup_dir.glob("orch_backup_*.db.gz"):
        if backup_file.stat().st_mtime < cutoff:
            backup_file.unlink()
            print(f"Removed old backup: {backup_file}")

if __name__ == "__main__":
    backup_database()
```

#### Scheduled Backups

**Linux (crontab)**:
```bash
# Daily backup at 2 AM
0 2 * * * /opt/orch-next/.venv/bin/python /opt/orch-next/scripts/backup_database.py

# Weekly full backup on Sunday at 3 AM
0 3 * * 0 /opt/orch-next/scripts/full_backup.sh
```

**Windows (Task Scheduler)**:
```powershell
# Create scheduled task for daily backup
$action = New-ScheduledTaskAction -Execute "python" -Argument "scripts\backup_database.py" -WorkingDirectory "C:\ORCH-Next"
$trigger = New-ScheduledTaskTrigger -Daily -At "2:00AM"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "ORCH-Next-Backup" -Action $action -Trigger $trigger -Settings $settings
```

### Recovery Procedures

#### Database Recovery

```python
# scripts/restore_database.py
import sqlite3
import gzip
import shutil
from pathlib import Path
from datetime import datetime

def restore_database(backup_file: str):
    """Restore database from backup"""
    
    backup_path = Path(backup_file)
    if not backup_path.exists():
        raise FileNotFoundError(f"Backup file not found: {backup_file}")
    
    # Create backup of current database
    current_db = Path("data/orch.db")
    if current_db.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        current_backup = Path(f"data/orch_pre_restore_{timestamp}.db")
        shutil.copy2(current_db, current_backup)
        print(f"Current database backed up to: {current_backup}")
    
    try:
        # Decompress and restore
        if backup_path.suffix == '.gz':
            with gzip.open(backup_path, 'rb') as f_in:
                with open(current_db, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        else:
            shutil.copy2(backup_path, current_db)
        
        # Verify restored database
        with sqlite3.connect(str(current_db)) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check")
            result = cursor.fetchone()[0]
            
            if result != "ok":
                raise Exception(f"Restored database failed integrity check: {result}")
        
        print(f"Database restored successfully from: {backup_file}")
        
    except Exception as e:
        print(f"Restore failed: {e}")
        # Restore original database if available
        if 'current_backup' in locals() and current_backup.exists():
            shutil.copy2(current_backup, current_db)
            print("Original database restored")
        raise

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python restore_database.py <backup_file>")
        sys.exit(1)
    
    restore_database(sys.argv[1])
```

#### Service Recovery

```bash
#!/bin/bash
# scripts/recover_service.sh

echo "Starting ORCH-Next service recovery..."

# Stop service
sudo systemctl stop orch-next

# Check for database corruption
python scripts/health_check.py
if [ $? -ne 0 ]; then
    echo "Database corruption detected, restoring from backup..."
    
    # Find latest backup
    LATEST_BACKUP=$(ls -t data/backups/orch_backup_*.db.gz | head -1)
    
    if [ -n "$LATEST_BACKUP" ]; then
        python scripts/restore_database.py "$LATEST_BACKUP"
    else
        echo "No backup found, manual intervention required"
        exit 1
    fi
fi

# Clear any stale locks
python -c "
from src.lock_manager import LockManager
lm = LockManager('data/orch.db')
lm.cleanup_expired_locks()
print('Cleared expired locks')
"

# Reset failed tasks
python -c "
from src.dispatcher import TaskDispatcher
import yaml
with open('config/production.yaml') as f:
    config = yaml.safe_load(f)
td = TaskDispatcher(config)
td.reset_failed_tasks()
print('Reset failed tasks')
"

# Start service
sudo systemctl start orch-next

# Wait for service to be ready
sleep 10

# Verify service health
curl -f http://localhost:8000/health
if [ $? -eq 0 ]; then
    echo "Service recovery completed successfully"
else
    echo "Service recovery failed, check logs"
    exit 1
fi
```

## Performance Tuning

### Database Optimization

#### SQLite Configuration

```python
# src/database.py
import sqlite3

def optimize_sqlite_connection(conn: sqlite3.Connection):
    """Apply SQLite performance optimizations"""
    
    # Enable WAL mode for better concurrency
    conn.execute("PRAGMA journal_mode=WAL")
    
    # Increase cache size (in KB)
    conn.execute("PRAGMA cache_size=10000")
    
    # Optimize for faster writes
    conn.execute("PRAGMA synchronous=NORMAL")
    
    # Enable foreign key constraints
    conn.execute("PRAGMA foreign_keys=ON")
    
    # Optimize query planner
    conn.execute("PRAGMA optimize")
    
    return conn
```

#### Database Maintenance

```python
# scripts/maintain_database.py
import sqlite3
from pathlib import Path

def maintain_database():
    """Perform database maintenance tasks"""
    
    db_path = Path("data/orch.db")
    
    with sqlite3.connect(str(db_path)) as conn:
        # Analyze query patterns
        conn.execute("ANALYZE")
        
        # Rebuild indexes
        conn.execute("REINDEX")
        
        # Vacuum database (reclaim space)
        conn.execute("VACUUM")
        
        # Update statistics
        conn.execute("PRAGMA optimize")
        
        print("Database maintenance completed")

if __name__ == "__main__":
    maintain_database()
```

### Application Performance

#### FastAPI Optimization

```python
# src/orchestrator.py
from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI(
    title="ORCH-Next",
    version="1.0.0",
    docs_url="/docs" if DEBUG else None,  # Disable docs in production
    redoc_url=None,  # Disable redoc
)

# Add compression middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Add trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "*.company.com"]
)

# Configure uvicorn for production
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.orchestrator:app",
        host="0.0.0.0",
        port=8000,
        workers=4,  # Number of worker processes
        worker_class="uvicorn.workers.UvicornWorker",
        access_log=False,  # Disable access logs for performance
        server_header=False,  # Don't send server header
        date_header=False,  # Don't send date header
    )
```

#### Connection Pooling

```python
# src/connection_pool.py
import sqlite3
import threading
from contextlib import contextmanager
from queue import Queue, Empty

class SQLiteConnectionPool:
    def __init__(self, database_path: str, max_connections: int = 10):
        self.database_path = database_path
        self.max_connections = max_connections
        self.pool = Queue(maxsize=max_connections)
        self.lock = threading.Lock()
        
        # Pre-populate pool
        for _ in range(max_connections):
            conn = self._create_connection()
            self.pool.put(conn)
    
    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.database_path,
            check_same_thread=False,
            timeout=30.0
        )
        # Apply optimizations
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA cache_size=10000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn
    
    @contextmanager
    def get_connection(self):
        try:
            conn = self.pool.get(timeout=5.0)
        except Empty:
            # Create temporary connection if pool exhausted
            conn = self._create_connection()
            temp_connection = True
        else:
            temp_connection = False
        
        try:
            yield conn
        finally:
            if temp_connection:
                conn.close()
            else:
                self.pool.put(conn)
    
    def close_all(self):
        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                conn.close()
            except Empty:
                break
```

### Memory Management

#### Memory Monitoring

```python
# scripts/memory_monitor.py
import psutil
import gc
import sys
from datetime import datetime

def monitor_memory():
    """Monitor application memory usage"""
    
    process = psutil.Process()
    memory_info = process.memory_info()
    
    print(f"Timestamp: {datetime.now()}")
    print(f"RSS Memory: {memory_info.rss / 1024 / 1024:.2f} MB")
    print(f"VMS Memory: {memory_info.vms / 1024 / 1024:.2f} MB")
    print(f"Memory Percent: {process.memory_percent():.2f}%")
    
    # Python garbage collection stats
    gc_stats = gc.get_stats()
    for i, stat in enumerate(gc_stats):
        print(f"GC Gen {i}: {stat}")
    
    # Force garbage collection if memory usage is high
    if process.memory_percent() > 80:
        print("High memory usage detected, forcing garbage collection")
        collected = gc.collect()
        print(f"Collected {collected} objects")

if __name__ == "__main__":
    monitor_memory()
```

## Security Operations

### Security Hardening

#### SSL/TLS Configuration

```python
# config/ssl_config.py
import ssl
from pathlib import Path

def create_ssl_context():
    """Create SSL context for HTTPS"""
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # Load certificates
    cert_file = Path("certs/server.crt")
    key_file = Path("certs/server.key")
    
    if cert_file.exists() and key_file.exists():
        context.load_cert_chain(str(cert_file), str(key_file))
    
    # Security settings
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    
    return context

# Start server with SSL
if __name__ == "__main__":
    import uvicorn
    ssl_context = create_ssl_context()
    
    uvicorn.run(
        "src.orchestrator:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile="certs/server.key",
        ssl_certfile="certs/server.crt",
        ssl_version=ssl.PROTOCOL_TLS,
        ssl_cert_reqs=ssl.CERT_NONE,
    )
```

#### Security Scanning

```bash
#!/bin/bash
# scripts/security_scan.sh

echo "Running security scans..."

# Python security scan
echo "Running Bandit security scan..."
bandit -r src/ -f json -o security_reports/bandit_report.json

# Dependency vulnerability scan
echo "Running Safety dependency scan..."
safety check --json --output security_reports/safety_report.json

# SAST scan with Semgrep
echo "Running Semgrep SAST scan..."
semgrep --config=auto src/ --json --output=security_reports/semgrep_report.json

# Generate security report
python scripts/generate_security_report.py

echo "Security scans completed. Check security_reports/ directory."
```

### Access Control

#### Role-Based Access Control (RBAC)

```python
# src/rbac.py
from enum import Enum
from typing import Set, Dict, List
from dataclasses import dataclass

class Permission(Enum):
    # Task permissions
    TASK_CREATE = "task:create"
    TASK_READ = "task:read"
    TASK_UPDATE = "task:update"
    TASK_DELETE = "task:delete"
    
    # System permissions
    SYSTEM_MONITOR = "system:monitor"
    SYSTEM_ADMIN = "system:admin"
    
    # User permissions
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"

@dataclass
class Role:
    name: str
    permissions: Set[Permission]
    description: str

# Define roles
ROLES: Dict[str, Role] = {
    "admin": Role(
        name="admin",
        permissions={
            Permission.TASK_CREATE, Permission.TASK_READ, 
            Permission.TASK_UPDATE, Permission.TASK_DELETE,
            Permission.SYSTEM_MONITOR, Permission.SYSTEM_ADMIN,
            Permission.USER_CREATE, Permission.USER_READ,
            Permission.USER_UPDATE, Permission.USER_DELETE
        },
        description="Full system access"
    ),
    "operator": Role(
        name="operator",
        permissions={
            Permission.TASK_CREATE, Permission.TASK_READ,
            Permission.TASK_UPDATE, Permission.SYSTEM_MONITOR
        },
        description="Task management and monitoring"
    ),
    "viewer": Role(
        name="viewer",
        permissions={
            Permission.TASK_READ, Permission.SYSTEM_MONITOR
        },
        description="Read-only access"
    )
}

def check_permission(user_role: str, required_permission: Permission) -> bool:
    """Check if user role has required permission"""
    role = ROLES.get(user_role)
    if not role:
        return False
    
    return required_permission in role.permissions
```

### Audit Logging

```python
# src/audit_logger.py
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

@dataclass
class AuditEvent:
    timestamp: str
    user_id: str
    username: str
    action: str
    resource: str
    resource_id: Optional[str]
    ip_address: str
    user_agent: str
    success: bool
    details: Dict[str, Any]

class AuditLogger:
    def __init__(self, log_file: str = "logs/audit.log"):
        self.logger = logging.getLogger("audit")
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_event(self, event: AuditEvent):
        """Log audit event"""
        event_dict = asdict(event)
        self.logger.info(json.dumps(event_dict))
    
    def log_authentication(self, username: str, success: bool, ip_address: str):
        """Log authentication attempt"""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            user_id="",
            username=username,
            action="authenticate",
            resource="auth",
            resource_id=None,
            ip_address=ip_address,
            user_agent="",
            success=success,
            details={}
        )
        self.log_event(event)
    
    def log_task_action(self, user_id: str, username: str, action: str, 
                       task_id: str, ip_address: str, details: Dict[str, Any]):
        """Log task-related action"""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            user_id=user_id,
            username=username,
            action=action,
            resource="task",
            resource_id=task_id,
            ip_address=ip_address,
            user_agent="",
            success=True,
            details=details
        )
        self.log_event(event)
```

## Troubleshooting

### Common Issues

#### High Memory Usage

**Symptoms**:
- Application consuming excessive memory
- Out of memory errors
- Slow response times

**Diagnosis**:
```bash
# Check memory usage
ps aux | grep python
top -p $(pgrep -f "uvicorn")

# Check for memory leaks
python scripts/memory_monitor.py

# Analyze memory usage patterns
grep "memory_percent" logs/orch-next.log | tail -100
```

**Solutions**:
1. Restart the service to clear memory
2. Reduce worker processes if using multiple workers
3. Implement connection pooling
4. Add memory limits to systemd service
5. Enable garbage collection monitoring

#### Database Lock Contention

**Symptoms**:
- "Database is locked" errors
- Slow database operations
- Task dispatch failures

**Diagnosis**:
```python
# Check for long-running transactions
python -c "
from src.lock_manager import LockManager
lm = LockManager('data/orch.db')
locks = lm.list_locks()
for lock in locks:
    print(f'Lock: {lock}')
"

# Check database integrity
sqlite3 data/orch.db "PRAGMA integrity_check;"
```

**Solutions**:
1. Enable WAL mode: `PRAGMA journal_mode=WAL`
2. Reduce transaction duration
3. Implement connection pooling
4. Add database timeout configuration
5. Clear expired locks manually

#### High CPU Usage

**Symptoms**:
- CPU usage consistently above 80%
- Slow API responses
- Task processing delays

**Diagnosis**:
```bash
# Profile CPU usage
python -m cProfile -o profile.stats src/orchestrator.py

# Analyze profile
python -c "
import pstats
p = pstats.Stats('profile.stats')
p.sort_stats('cumulative').print_stats(20)
"

# Check for busy loops
strace -p $(pgrep -f uvicorn) -c
```

**Solutions**:
1. Optimize database queries
2. Add caching for frequently accessed data
3. Implement async/await properly
4. Reduce monitoring frequency
5. Scale horizontally with load balancer

### Log Analysis

#### Error Pattern Analysis

```bash
# scripts/analyze_logs.sh

echo "Analyzing error patterns..."

# Count error types
echo "Error frequency:"
grep -i error logs/orch-next.log | \
  jq -r '.message' | \
  sort | uniq -c | sort -nr | head -10

# Find slow requests
echo "Slow requests (>2s):"
jq 'select(.duration_ms > 2000) | {timestamp, endpoint, duration_ms}' \
  logs/orch-next.log | head -10

# Authentication failures
echo "Authentication failures:"
jq 'select(.event_type == "auth_failure") | {timestamp, username, ip_address}' \
  logs/audit.log | tail -20

# Task failure analysis
echo "Task failure patterns:"
jq 'select(.event_type == "task.failed") | .data.error' \
  logs/orch-next.log | sort | uniq -c | sort -nr
```

#### Performance Analysis

```python
# scripts/performance_analysis.py
import json
import statistics
from collections import defaultdict
from datetime import datetime, timedelta

def analyze_performance():
    """Analyze performance metrics from logs"""
    
    response_times = defaultdict(list)
    error_counts = defaultdict(int)
    
    with open("logs/orch-next.log") as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                
                # Collect response times
                if "duration_ms" in log_entry:
                    endpoint = log_entry.get("endpoint", "unknown")
                    duration = log_entry["duration_ms"]
                    response_times[endpoint].append(duration)
                
                # Count errors
                if log_entry.get("levelname") == "ERROR":
                    error_type = log_entry.get("message", "unknown")
                    error_counts[error_type] += 1
                    
            except json.JSONDecodeError:
                continue
    
    # Generate performance report
    print("Performance Analysis Report")
    print("=" * 50)
    
    for endpoint, times in response_times.items():
        if len(times) > 10:  # Only analyze endpoints with sufficient data
            avg_time = statistics.mean(times)
            p95_time = statistics.quantiles(times, n=20)[18]  # 95th percentile
            
            print(f"\nEndpoint: {endpoint}")
            print(f"  Average response time: {avg_time:.2f}ms")
            print(f"  95th percentile: {p95_time:.2f}ms")
            print(f"  Total requests: {len(times)}")
    
    print(f"\nTop Errors:")
    for error, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {error}: {count}")

if __name__ == "__main__":
    analyze_performance()
```

### Emergency Procedures

#### Service Recovery

```bash
#!/bin/bash
# scripts/emergency_recovery.sh

echo "EMERGENCY: Starting service recovery procedure"

# Stop all related services
sudo systemctl stop orch-next
sudo systemctl stop nginx  # If using reverse proxy

# Kill any remaining processes
pkill -f "uvicorn.*orchestrator"

# Check disk space
df -h
if [ $(df / | tail -1 | awk '{print $5}' | sed 's/%//') -gt 90 ]; then
    echo "WARNING: Low disk space detected"
    # Clean up old logs
    find logs/ -name "*.log.*" -mtime +7 -delete
    find data/backups/ -name "*.gz" -mtime +30 -delete
fi

# Restore from backup if database is corrupted
if ! python scripts/health_check.py; then
    echo "Database corruption detected, restoring from backup"
    LATEST_BACKUP=$(ls -t data/backups/orch_backup_*.db.gz | head -1)
    if [ -n "$LATEST_BACKUP" ]; then
        python scripts/restore_database.py "$LATEST_BACKUP"
    fi
fi

# Clear temporary files
rm -rf /tmp/orch-next-*
rm -rf data/locks/*.lock

# Start services
sudo systemctl start orch-next
sleep 10
sudo systemctl start nginx

# Verify recovery
if curl -f http://localhost:8000/health; then
    echo "Emergency recovery completed successfully"
    # Send notification
    curl -X POST -H 'Content-type: application/json' \
         --data '{"text":"ORCH-Next emergency recovery completed successfully"}' \
         "$SLACK_WEBHOOK_URL"
else
    echo "Emergency recovery failed - manual intervention required"
    exit 1
fi
```

#### Data Recovery

```python
# scripts/data_recovery.py
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timedelta

def recover_lost_tasks():
    """Attempt to recover tasks from logs when database is corrupted"""
    
    recovered_tasks = []
    
    # Parse logs to find task creation events
    log_file = Path("logs/orch-next.log")
    if not log_file.exists():
        print("No log file found for recovery")
        return
    
    with open(log_file) as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                
                if log_entry.get("event_type") == "task.created":
                    task_data = log_entry.get("data", {})
                    recovered_tasks.append({
                        "task_id": task_data.get("task_id"),
                        "core_id": task_data.get("core_id"),
                        "status": "recovered",
                        "created_at": log_entry.get("timestamp"),
                        "metadata": task_data.get("metadata", {})
                    })
                    
            except json.JSONDecodeError:
                continue
    
    # Save recovered tasks
    recovery_file = Path(f"data/recovered_tasks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(recovery_file, 'w') as f:
        json.dump(recovered_tasks, f, indent=2)
    
    print(f"Recovered {len(recovered_tasks)} tasks to {recovery_file}")
    
    # Optionally restore to database
    if input("Restore tasks to database? (y/N): ").lower() == 'y':
        restore_tasks_to_database(recovered_tasks)

def restore_tasks_to_database(tasks):
    """Restore recovered tasks to database"""
    
    with sqlite3.connect("data/orch.db") as conn:
        cursor = conn.cursor()
        
        for task in tasks:
            cursor.execute("""
                INSERT OR IGNORE INTO tasks 
                (task_id, core_id, status, created_at, metadata)
                VALUES (?, ?, ?, ?, ?)
            """, (
                task["task_id"],
                task["core_id"],
                task["status"],
                task["created_at"],
                json.dumps(task["metadata"])
            ))
        
        conn.commit()
        print(f"Restored {len(tasks)} tasks to database")

if __name__ == "__main__":
    recover_lost_tasks()
```

## Best Practices

### Development Best Practices

1. **Code Quality**:
   - Use type hints throughout the codebase
   - Maintain test coverage above 80%
   - Follow PEP 8 style guidelines
   - Use async/await for I/O operations

2. **Security**:
   - Never commit secrets to version control
   - Use environment variables for configuration
   - Implement proper input validation
   - Regular security dependency updates

3. **Performance**:
   - Profile code regularly
   - Use connection pooling
   - Implement caching where appropriate
   - Monitor memory usage

### Operational Best Practices

1. **Monitoring**:
   - Set up comprehensive alerting
   - Monitor key business metrics
   - Regular health checks
   - Capacity planning

2. **Backup and Recovery**:
   - Automated daily backups
   - Test recovery procedures regularly
   - Document recovery processes
   - Maintain backup retention policy

3. **Deployment**:
   - Use blue-green deployments
   - Implement canary releases
   - Maintain rollback procedures
   - Test in staging environment

4. **Documentation**:
   - Keep documentation up to date
   - Document operational procedures
   - Maintain runbooks for common issues
   - Regular documentation reviews

---

This operations guide provides comprehensive procedures for managing ORCH-Next in production environments. Regular review and updates of these procedures ensure reliable system operation and quick issue resolution.

## SBOM 発行と CI 強化手順（付録）

本プロジェクトでは、セキュリティとコンプライアンスのため SBOM（Software Bill of Materials）の自動生成と、機密情報スキャン／EOL チェックを CI に組み込みます。

### SBOM 生成（CycloneDX）

- 依存のインストール: `pip install cyclonedx-bom`
- 生成コマンド: `cyclonedx-bom -o observability/sbom/sbom.json`
- 成果物の保存: `observability/sbom/sbom.json` をアーティファクトへアップロード
- 署名・検証（PoC）: RSA-PSS(SHA256) による SBOM 署名と検証を導入

### SBOM 署名/検証（PoC RSA）

SBOM の改ざん検知のため、PoC として RSA-PSS(SHA256) による署名・検証を実施します。

```bash
# 署名
python scripts/sbom/sign_sbom.py --sbom observability/sbom/sbom.json \
  --out observability/sbom/sbom.sig --keys-dir observability/sbom/keys

# 検証（失敗時は非ゼロ終了）
python scripts/sbom/verify_sbom.py --sbom observability/sbom/sbom.json \
  --sig observability/sbom/sbom.sig --keys-dir observability/sbom/keys
```

CI では `.github/workflows/ci.yml` に署名/検証ステップを組み込み、検証失敗時はジョブを fail にします。鍵は CI 実行時に短命で生成され、`observability/sbom/keys/` に保存されます（将来的に KMS/Keyless Sigstore へ移行）。

### CI 追加ステップ

`.github/workflows/ci.yml` に以下のステップを追加しています:

- Secret scan: `python scripts/ops/scan_secrets.py`
- EOL check: `python scripts/ops/check_eol.py`
- SBOM artifact upload: `actions/upload-artifact@v4`

### リソースガード（準備）

将来的なデーモン同梱に向け、CPU 使用率・ディスク空き容量の簡易チェックを行う `scripts/ops/resource_guard.py` を追加予定（閾値既定: CPU 80%、ディスク空き 1GB）。CI では non-blocking とし、閾値超過時は警告を発します（`RESOURCE_GUARD_STRICT=true` で fail に変更可能）。