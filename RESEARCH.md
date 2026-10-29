# depenBot — market and open-source research

Research date: 23 October 2026. Scope: project dependency vulnerability monitoring, advisory intelligence, remediation, and email/Telegram notifications. This is a documentation and repository review, not a hands-on product benchmark or security audit. Feature availability depends on plan, ecosystem, configuration, and product version. No paid accounts were evaluated.

## Recommendation

Build a dependency vulnerability monitoring and response product using existing scanning engines. The strongest proposed position is: **know which projects are affected, why the match is credible, who must act, and whether the notification reached its destination.**

Email is established functionality. Telegram CVE bots already exist. Continuous monitoring, SBOMs, EPSS, and reachability also exist. Combining these into an easier, trustworthy workflow is a product hypothesis to validate with buyers, not an unclaimed market category.

## Existing services

| Service | Verified capabilities | Documented limitation or evaluation concern | Lesson for depenBot |
| --- | --- | --- | --- |
| GitHub Dependabot | Dependency graph alerts, fixed-version information, email/digests, security updates, assignment and API workflows. | Alerts use the default branch and reviewed GitHub advisories; archived repositories are excluded. Initial enablement does not notify for the existing vulnerability backlog. | Explicit onboarding summary, inventory freshness, branch/release scope, and notification previews. |
| Snyk | SCM integrations, dependency vulnerability workflows, configurable issue/summary notifications, reachability analysis. | Reachability support varies by language/integration; its documentation says “no path found” does not establish unexploitable code. | Show coverage and analysis uncertainty; never interpret unknown reachability as safe. |
| Mend / Renovate | Automated dependency PRs; Mend Remediate adds targeted security fixes, transitive scanning, and workflow rules. | Remediation can fail when the necessary manifest or compatible version is missing, a language is unsupported, or no fixed version exists. | Distinguish affected, fix available, upgrade proposed, and fix verified. |
| Socket | Supply-chain behavior and malware detections, CVEs, policy controls, broad integrations, filtered notification subscriptions. | Its ecosystem matrix shows different maturity and feature coverage. Its notification page lists email and Teams, with Slack marked coming soon in that workflow. | Publish a feature-by-ecosystem matrix; distinguish integration marketing from the exact supported workflow. |
| GitLab dependency scanning | SBOM-driven background re-evaluation when advisories change; CI and vulnerability reporting. | The reviewed continuous-scanning page says new findings do not generate notifications, Go pseudo-versions are unsupported, and resolution requires a fresh scan. Listed as Ultimate. | Notification coverage and reliable resolution tracking need explicit acceptance criteria. |
| Vulert | Uploaded manifests/SBOMs, continuous monitoring without source access, email, API/CI, recommended fixes, and paid-tier Jira/Slack/reporting features. | The observed inventory is the uploaded dependency file; it must be updated to represent current software. Published pages do not establish native Telegram support. | Closest overlap with a lightweight monitoring MVP; upload-only monitoring is not differentiation. |
| Aikido | Dependency CVE scanning with configurable development-dependency behavior. | Its dev-dependency documentation says these CVEs are excluded by default and gives SvelteKit as an example where dev-marked dependencies can ship. | Preserve dependency scope and let customers choose policy instead of silently discarding dev dependencies. |

Sources: [Dependabot alerts](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-alerts), [Snyk notifications](https://learn.snyk.io/lesson/configuring-notifications/), [Snyk reachability documentation](https://github.com/snyk/user-docs/blob/main/scan-fix-and-prevent/manage-risk/prioritize-issues-for-fixing/reachability-analysis.md), [Mend remediation](https://docs.mend.io/integrations/latest/mend-remediate-and-renovate), [Socket ecosystem support](https://docs.socket.dev/docs/language-support), [Socket notifications](https://docs.socket.dev/docs/notifications), [GitLab continuous scanning](https://docs.gitlab.com/user/application_security/dependency_scanning/continuous_dependency_scanning/), [Vulert onboarding](https://vulert.com/developers/getting-started/add-application), [Vulert plans](https://vulert.com/pricing), [Aikido development dependencies](https://help.aikido.dev/code-scanning/scanning-practices/scanning-dev-dependencies-for-cves).

An integration absent from a reviewed page is **not proof that a vendor cannot support it** through an API, webhook, partner, or custom contract. No claim is made that these products universally lack enterprise governance or delivery tracking.

## GitHub projects worth studying or reusing

The activity dates below come from GitHub repository `pushed_at`, checked on the research date. Recent pushes demonstrate activity, not release quality or security. All six main candidates were non-archived at the time checked.

| Repository | Last push checked | Repository license metadata | Useful role | What remains to build or verify |
| --- | --- | --- | --- | --- |
| [Dependency-Track](https://github.com/DependencyTrack/dependency-track) | 2026-10-22 | Apache-2.0 | Closest open-source platform: SBOM portfolio analysis, policies, VEX, vulnerability intelligence, notifications. | Evaluate extending it before building another platform. Supplied inventory quality and product-version migration matter. |
| [OSV-Scanner](https://github.com/google/osv-scanner) | 2026-10-22 | Apache-2.0 | Primary candidate for dependency inventory/scanning; source/container support and remediation capabilities. | A CLI/library does not supply our tenancy, ownership, notification lifecycle, or operational service. Validate exact parsers and release behavior. |
| [Trivy](https://github.com/aquasecurity/trivy) | 2026-10-23 | Apache-2.0 | Broad scanner adapter, especially containers and OS packages as scope grows. | Our service still needs inventory history, policies, tenant boundaries, and delivery tracking. |
| [Grype](https://github.com/anchore/grype) | 2026-10-22 | Apache-2.0 | Image/filesystem/SBOM scanning; EPSS, KEV, risk scoring, OpenVEX. | Risk enrichment already exists; do not market it as novel. Compare matching results on representative fixtures. |
| [Renovate](https://github.com/renovatebot/renovate) | 2026-10-23 | AGPL-3.0 | Mature update and remediation automation. | Its OSV vulnerability-alert mode is documented as experimental, off by default, and direct-dependency-only. Review license obligations for the intended distribution/integration model. |
| [BotPEASS](https://github.com/peass-ng/BotPEASS) | 2026-10-22 | Apache-2.0 | Keyword CVE monitoring with Telegram and other destinations; scheduled GitHub workflow. | Keyword matching does not establish that a project's installed package version is affected. Reviewed README does not establish tenant isolation, inventory matching, SLAs, or enterprise administration. |

[dependabot-core](https://github.com/dependabot/dependabot-core) is also active (2026-10-23; MIT metadata). It supplies update-PR logic; it is not the entire hosted Dependabot service.

[Bot-CVE-Notif](https://github.com/JMousqueton/Bot-CVE-Notif) adds vendor-oriented CVE notifications to several channels. It is non-archived, but its last checked push was 2024-12-12; do not assume active maintenance. GitHub did not report a recognized repository license in this check, so reuse requires examining explicit license terms.

Licenses above are repository metadata, not a completed dependency/data redistribution review. Examine pinned releases and their dependencies before adoption.

Supporting documentation: [Dependency-Track platform](https://docs.dependencytrack.org/), [notification publishers](https://docs.dependencytrack.org/integrations/notifications/), [OSV-Scanner](https://google.github.io/osv-scanner/), [Grype README](https://github.com/anchore/grype/blob/main/README.md), [Renovate OSV mode](https://docs.renovatebot.com/configuration-options/#osvvulnerabilityalerts).

Dependency-Track's default-branch README currently describes v5 and a v4 maintenance/EOL transition, while the reviewed `docs.dependencytrack.org` landing page labels itself v4.14. Pin a release and matching documentation before making integration decisions. Its reviewed notification documentation lists email/webhooks and several messaging publishers, but not a built-in Telegram publisher; an adapter remains possible.

## Concrete reported issues

These were open GitHub reports when inspected. They are evidence of reported failure modes, **not independently reproduced defects**, and may change or be fixed after this review.

| Report | Reported problem | Requirement it motivates |
| --- | --- | --- |
| [Dependency-Track #7731](https://github.com/DependencyTrack/dependency-track/issues/7731) | Query timeouts reportedly prevent some scheduled email summaries after a 5.1 upgrade. | Bound digest queries, checkpoint progress, expose failures, and support replay. |
| [Dependency-Track #7721](https://github.com/DependencyTrack/dependency-track/issues/7721) | Suppression reportedly updates findings but leaves portfolio counts stale in 5.2.0. | One authoritative lifecycle with consistent, reconcilable projections. |
| [OSV-Scanner #1754](https://github.com/google/osv-scanner/issues/1754) | Go pseudo-version matching reportedly produces false positives. | Ecosystem-specific versions; unsupported semantics must be visible. |
| [OSV-Scanner #2881](https://github.com/google/osv-scanner/issues/2881) | A local workspace link reportedly matches an unrelated public malicious package. | Preserve package origin, workspace identity, and registry provenance. |
| [Trivy #11360](https://github.com/aquasecurity/trivy/issues/11360) | Yarn workspace development dependencies reportedly appear as production dependencies. | Preserve scope per dependency path; monorepo fixtures are mandatory. |
| [Grype #3757](https://github.com/anchore/grype/issues/3757) | A CPE-backed advisory reportedly fails to match an affected PyPI PURL. | Report identifier coverage and uncertainty; avoid unsupported name-only joins. |

## Opportunities to validate

1. **Actionable alerts:** exact affected version, dependency path where available, source evidence, owner, fix status, due date, and authenticated action link.
2. **Transparent monitoring:** distinguish clean inventory from stale inventory, parser failure, missing lockfile, expired connector, and outdated advisory feeds.
3. **Controlled noise:** group related findings, deduplicate advisory aliases, send meaningful changes, and offer digests and escalation.
4. **Telegram as a supported workflow:** verified destination binding, privacy controls, rate-aware delivery, and permission-checked acknowledgement.
5. **Small-team usability with enterprise controls:** prove onboarding simplicity and operational reliability before claiming enterprise readiness.

Interview 5–10 target teams. Ask which tools they already pay for, why alerts are ignored, whether Telegram is allowed, what evidence audits require, which deployment models are mandatory, and what they would pay to replace or complement an existing tool. Telegram may fit some engineering teams and be disallowed by others.

## Intelligence and notification foundations

- [OSV](https://osv.dev/): package-oriented advisory data; use ecosystem and version-aware matching. Preserve aliases and provenance instead of treating overlapping feeds as independent confirmations.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): evidence of known exploitation, useful for prioritization. Absence is not proof of no exploitation.
- [FIRST EPSS](https://www.first.org/epss/): estimated probability of exploitation of a published CVE within 30 days. It is neither severity nor the probability our particular application is exploitable.
- [Telegram Bot API FAQ](https://core.telegram.org/bots/faq): per-chat, group, and broadcast limits require queueing and handling HTTP 429. Provider acceptance is not a human acknowledgement.

Use CVE identifiers where available, but support GHSA and other advisories without CVEs. Keep severity, exploitation evidence, matching confidence, and business priority separate.
