import sqlite3
from datetime import datetime
from pathlib import Path
p = Path('data/quality_metrics.db')
print('DB path:', p.as_posix(), 'exists:', p.exists())
with sqlite3.connect(p.as_posix()) as conn:
    conn.execute(
        """
        INSERT INTO quality_metrics (timestamp, test_coverage, code_complexity, error_rate, performance_score, quality_issue, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now().isoformat(),
            0.86,
            3.1,
            0.018,
            0.9,
            0,
            'Manual recent metric inserted for dashboard preview'
        )
    )
    conn.commit()
print('Inserted one recent metric at', datetime.now().isoformat())
