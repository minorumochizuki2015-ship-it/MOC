UI-Audit Checklist (Multi-layer Guard)

- [ ] Axe accessibility audit passes (no critical issues)
- [ ] Visual regression audit passes (baseline unchanged or approved)
- [ ] LCP within threshold (project_rules.yaml performance target)
- [ ] Lighthouse report generated and stored in observability/ui/report/lighthouse
- [ ] Linkinator markdown report generated and stored in observability/ui/report/linkinator.md
- [ ] Playwright artifacts collected on failure (HTML report, screenshots, traces)
- [ ] Accountability card generated in ORCH/patches/<YYYY-MM>/root_cause_card_*.md
- [ ] CI job statuses green; any failures have actionable logs and artifacts