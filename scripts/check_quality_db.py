import sqlite3, json
from pathlib import Path
p = Path('data/quality_metrics.db')
print('DB exists:', p.exists(), 'size:', p.stat().st_size if p.exists() else 0)
if not p.exists():
    raise SystemExit(0)
with sqlite3.connect(p.as_posix()) as conn:
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM quality_metrics')
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM quality_metrics WHERE datetime(timestamp) >= datetime('now','-1 day')")
    recent1 = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM quality_metrics WHERE datetime(timestamp) >= datetime('now','-7 day')")
    recent7 = c.fetchone()[0]
    c.execute('SELECT timestamp FROM quality_metrics ORDER BY timestamp DESC LIMIT 1')
    last = c.fetchone()
    print(json.dumps({'total': total, 'recent1d': recent1, 'recent7d': recent7, 'last_timestamp': last[0] if last else None}))
