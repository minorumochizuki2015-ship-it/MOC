diff --git a/.trae/rules/DIFF_GUARD.yaml b/.trae/rules/DIFF_GUARD.yaml
new file mode 100644
index 0000000..2b34438
--- /dev/null
+++ b/.trae/rules/DIFF_GUARD.yaml
@@ -0,0 +1,68 @@
+# Diff Governance Guard (DIFF_GUARD)
+# Purpose: Enforce "diff preview → validation → integration" before any write operations,
+# with special caution and stricter approvals for deletions.
+
+name: DIFF_GUARD
+version: 1.0.0
+owner: Governance
+status: active
+
+policy:
+  require_diff_preview: true
+  require_patch_artifact: true          # Must save unified diff under ORCH/patches/YYYY-MM/
+  require_approvals_on_deletion: true   # Deletions require multi-party approval
+  min_approvals:
+    default: 1
+    deletion: 2
+    large_deletion: 3                   # >=25 lines removed or file removal
+  thresholds:
+    large_deletion_lines: 25
+
+  commit_requirements:
+    - include_patch_path: true          # e.g., ORCH/patches/2025-10/<change>.diff.md
+    - include_change_id: true           # e.g., A00X or WORK tag
+    - include_summary: true             # one-line rationale
+
+  ci_gates:
+    - eol_check                         # ensure LF/EOL consistency
+    - compare_gate                      # diff present and referenced
+    - clone_gate                        # builds clean in fresh clone
+    - pytest_subset: "-q -k figma2ui" # smoke for impacted module, adjust per change
+
+  automerge_rules:
+    allow:
+      - docs_minor                      # Markdown only, <=5 lines changed, no deletions
+    block:
+      - rules_changes                   # Any edits under .trae/rules
+      - deletions_over_threshold        # >= thresholds.large_deletion_lines
+
+  exceptions:
+    - emergency_hotfix:                 # allow single maintainer with post-mortem within 24h
+        allowed: false                  # disabled by default; enable only via Governance sign-off
+
+procedures:
+  preview_new_files:
+    - step: "intent-to-add"
+      command: "git add -N <file>"     # enables diff for new files
+    - step: "generate diff"
+      command: "git diff -- <file> > ORCH/patches/YYYY-MM/<name>.diff.md"
+
+  merge_process:
+    - "Prepare patch (diff)"
+    - "Validate via CI gates"
+    - "Collect approvals per policy"
+    - "Merge only when all gates PASS"
+
+auditing:
+  record_locations:
+    - ORCH/patches/YYYY-MM/
+    - ORCH/STATE/CHECKLISTS/
+  reviewers:
+    - WORK1
+    - WORK2
+    - Design-UI
+
+notes:
+  - "Deletions must include rationale and rollback plan."
+  - "Use JSONL logging to observability/ui/skills/ for any skill-affecting changes."
+  - "Reference Agent Spec and CMD.yaml when routing rules are impacted."
\ No newline at end of file
