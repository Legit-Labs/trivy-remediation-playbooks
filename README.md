# Trivy Supply Chain Compromise — Remediation Playbooks

AI-agent-ready playbooks for detecting and remediating the Trivy ecosystem supply chain compromise (March 19-22, 2026, [GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)).

## What happened

A threat actor compromised multiple Trivy distribution channels simultaneously:
- Malicious trivy binary **v0.69.4** published to GitHub Releases, APT/RPM repos, and container registries
- **76 of 77** trivy-action GitHub Action tags force-pushed with credential-stealing malware
- All **setup-trivy** tags replaced with malicious commits
- Malicious Docker Hub images **v0.69.5** and **v0.69.6**

The injected infostealer dumped CI runner process memory, harvested credentials from 50+ filesystem paths, and exfiltrated encrypted data to attacker infrastructure.

## Playbooks

### [Detection & Response](trivy-analysis-playbook.md)

Determine if your organization was compromised. This playbook walks through:

- Identifying all trivy usage across your GitHub org (actions, binaries, Docker images)
- Downloading and searching all GitHub Actions run logs from the exposure window
- Detecting compromised binary versions, tag-based action references, and Docker pulls
- Checking for indicators of compromise (exfiltration repos, memory access patterns)
- Secret rotation guidance if compromise is detected

### [Hardening & Prevention](trivy-hardening-playbook.md)

Eliminate the attack surfaces that made this compromise possible:

- Pin GitHub Actions to commit hashes (not mutable tags)
- Bypass `setup-trivy` entirely with `skip-setup-trivy: true`
- Replace the third-party APT repo with direct `.deb` download + hardcoded SHA256
- Remove Docker image tag dependencies by upgrading to composite actions
- Complete hardened workflow example with architecture-aware binary installation

## Using with an AI agent

These playbooks are designed to be executed by an AI coding agent (Claude Code, Cursor, GitHub Copilot, etc.) with access to the `gh` CLI and your organization's repositories.

### Detection

Give the agent the detection playbook and ask it to:

> Run the Trivy supply chain compromise detection playbook against our GitHub org. Download all workflow run logs from the exposure window (March 19-22, 2026), search for compromised versions, check for indicators of compromise, and report findings.

The agent will:
1. Set the variables (`ORG`, `SINCE`, `UNTIL`, `LOG_DIR`)
2. Enumerate all repos and workflow runs via `gh` CLI
3. Download logs in parallel and search for compromised versions
4. Check for IOCs (tpcp-docs repos, memory access, tag-based references)
5. Verify all trivy-action commit hashes predate the compromise
6. Report a summary of findings per repo

### Hardening

Give the agent the hardening playbook and ask it to:

> Follow the Trivy hardening playbook to secure our CI pipelines. Compute SHA256 checksums for the safe trivy version, find and replace all APT repo installs with direct downloads, pin all actions to commit hashes, and add skip-setup-trivy to all trivy-action calls.

The agent will:
1. Determine the safe trivy version and compute `.deb` checksums
2. Search all workflow files across the org for trivy references
3. Replace APT repo installs with direct `.deb` download + SHA256 verification
4. Ensure all trivy-action references use commit hashes
5. Add `skip-setup-trivy: true` where missing
6. Create branches and PRs for each affected repo

### Tips for agents

- The playbooks use environment variables (`$ORG`, `$TRIVY_VERSION`, etc.) defined at the top of each file. The agent should set these before running commands.
- Log downloads can be parallelized with `xargs -P 10` for faster results.
- The detection playbook includes false positive guidance — branch names, env vars, and scan output that mention "trivy" are not indicators of compromise.
- The hardening playbook includes architecture-aware install snippets (amd64 + arm64) with per-architecture SHA256 checksums.

## About

Created by [Legit Security](https://www.legitsecurity.com) — protecting your software supply chain from code to cloud.

## License

MIT
