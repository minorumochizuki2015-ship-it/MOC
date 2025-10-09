# Multi-terminal Roles and Handshake

This directory defines simple, file-based coordination between terminals:

- role_status.json: current status for each role (idle/in_progress/blocked/completed). Update this when you start/finish a task.
- heartbeat.json: last heartbeat timestamps per role. Update periodically to indicate liveness.
- handoff_queue.json: queue of tasks handed from Auditor to Executors and back.

Workflow:
1) Commander assigns tasks → Auditor enqueues into handoff_queue.json.
2) Executors pick tasks, set role_status to in_progress, update heartbeat.
3) Executors finish, push results summary paths into handoff_queue.json.
4) Auditor validates, aggregates, and either approves or returns to queue.
5) Commander reviews aggregate and approves final state.