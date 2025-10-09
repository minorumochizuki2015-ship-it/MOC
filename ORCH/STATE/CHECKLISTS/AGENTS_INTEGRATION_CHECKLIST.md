# Agents Integration Checklist

Created: 2025-10-08
Owner: CMD

## API Endpoints
- [x] /status responds 200
- [x] /api/system-health responds 200
- [x] /api/agents/list responds 200
- [x] /api/agents/register responds 200
- [x] /api/agents/heartbeat responds 200
- [x] /api/agents/report responds 200

## Data Persistence
- [ ] data/agents_registry.json created and writable
- [ ] Agent registration de-duplicates by id
- [ ] Heartbeat updates status and timestamp
- [ ] Reports append entries with artifacts

## Automation
- [x] scripts/ops/audit_endpoints.py runs and writes reports
- [x] NonStop_Audit.md gets appended with summary lines
- [x] Continuous audit runner launched (every 2 min)
- [x] CI job triggers audit on commit

## UI (Backend-first)
- [x] Agent Management tab available (/agents)
 - [x] Route list debug endpoint available (/api/debug/routes)