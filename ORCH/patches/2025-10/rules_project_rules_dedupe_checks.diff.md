diff --git a/.trae/rules/project_rules.yaml b/.trae/rules/project_rules.yaml
index 143a546..37685ef 100644
--- a/.trae/rules/project_rules.yaml
+++ b/.trae/rules/project_rules.yaml
@@ -51,6 +51,7 @@ specs:                         # required agent specs
   web_verify:        {file: ".trae/rules/Web-Verify.yaml"}
   audit_rules:       {file: ".trae/rules/AUDIT_rules.yaml"}
   approvals:         {file: ".trae/rules/APPROVALS.yaml"}
+  diff_guard:        {file: ".trae/rules/DIFF_GUARD.yaml",         min_version: 1}
   cmd:               {file: ".trae/rules/CMD.yaml"}
   agent_spec_shared: {file: ".trae/rules/Agent Spec.yaml"}
 
@@ -331,6 +332,8 @@ ci:
     - sbom_generate_sign_verify
     - secret_scan
     - eol_check
+    - compare_gate            # Verify diff artifact present and referenced
+    - clone_gate              # Validate clean build from fresh clone
     - bandit
   enforce_order: true
   continue_on_mypy_error: true
@@ -347,17 +350,10 @@ ci:
       - mypy
       - pytest
       - coverage
-      - sbom_sign_verify
-      - secret_scan
-      - eol_check
-      - pre_commit
-      - flake8
-      - mypy
-      - pytest
       - diff_coverage
       - sbom_generate_sign_verify
       - secret_scan
-      - eol_chec
+      - eol_check
     required_reviews: 1
     codeowners_enforced: true
     dismiss_stale_reviews: true
