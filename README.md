# Supply Chain Compromise — Remediation Playbooks

AI-agent-ready playbooks for detecting and remediating the Trivy supply chain compromise and the subsequent incidents that originated from it:

- **Trivy** (March 19-22, 2026) — [Detection](trivy-analysis-playbook.md) | [Hardening](trivy-hardening-playbook.md)
- **LiteLLM** (March 24, 2026) — [Detection](litellm-detection-playbook.md) | [Hardening](litellm-hardening-playbook.md)

---

## Trivy (GHSA-69fq-xp46-6x23)

### What happened

A threat actor compromised multiple Trivy distribution channels simultaneously:
- Malicious trivy binary **v0.69.4** published to GitHub Releases, APT/RPM repos, and container registries
- **76 of 77** trivy-action GitHub Action tags force-pushed with credential-stealing malware
- All **setup-trivy** tags replaced with malicious commits
- Malicious Docker Hub images **v0.69.5** and **v0.69.6**

The injected infostealer dumped CI runner process memory, harvested credentials from 50+ filesystem paths, and exfiltrated encrypted data to attacker infrastructure.

### An AI Agent Running These Playbooks Will:

#### [Detection & Response](trivy-analysis-playbook.md)

- **Identify** all trivy usage across your GitHub org — actions, binaries, Docker images
- **Download** all GitHub Actions run logs from the exposure window in parallel
- **Detect** compromised binary versions (v0.69.4/5/6), tag-based action references, and unverified Docker pulls
- **Verify** every trivy-action commit hash predates the compromise
- **Check** for indicators of compromise — exfiltration repos, process memory access, typosquatted domains
- **Report** a per-repo summary of findings with secret rotation guidance

#### [Hardening & Prevention](trivy-hardening-playbook.md)

- **Compute** SHA256 checksums for a known-safe trivy `.deb` release
- **Replace** all third-party APT repo installs with direct `.deb` download + hardcoded SHA256
- **Pin** all GitHub Action references to immutable commit hashes
- **Bypass** `setup-trivy` entirely by adding `skip-setup-trivy: true`
- **Upgrade** Docker-based trivy-action versions to composite actions (eliminates Docker image attack surface)
- **Create** branches and PRs for each affected repo

### Usage

These playbooks are designed to be executed by an AI coding agent (Claude Code, Cursor, GitHub Copilot, etc.) with access to the `gh` CLI and your organization's repositories.

#### Detection — paste this prompt to your agent:

```
Run the Trivy supply chain compromise detection playbook against our
GitHub org. Download all workflow run logs from the exposure window
(March 19-22, 2026), search for compromised versions, check for
indicators of compromise, and report findings.
```

#### Hardening — paste this prompt to your agent:

```
Follow the Trivy hardening playbook to secure our CI pipelines.
Compute SHA256 checksums for the safe trivy version, find and replace
all APT repo installs with direct downloads, pin all actions to commit
hashes, and add skip-setup-trivy to all trivy-action calls.
```

#### Tips for agents

- The playbooks use environment variables (`$ORG`, `$TRIVY_VERSION`, etc.) defined at the top of each file. The agent should set these before running commands.
- Log downloads can be parallelized with `xargs -P 10` for faster results.
- The detection playbook includes false positive guidance — branch names, env vars, and scan output that mention "trivy" are not indicators of compromise.
- The hardening playbook includes architecture-aware install snippets (amd64 + arm64) with per-architecture SHA256 checksums.

---

## LiteLLM ([advisory](https://docs.litellm.ai/blog/security-update-march-2026))

### What happened

On March 24, 2026, two compromised versions of the `litellm` Python package — **v1.82.7** and **v1.82.8** — were published directly to PyPI. The compromise originated from the Trivy dependency in LiteLLM's CI/CD workflow — the attacker leveraged this to bypass official pipelines and upload malicious packages directly to PyPI. The payload exfiltrated environment variables, SSH keys, cloud credentials, and Kubernetes tokens to `models.litellm.cloud`.

### An AI Agent Running These Playbooks Will:

#### [Detection & Assessment](litellm-detection-playbook.md)

- **Search** all code across your GitHub org for litellm in dependency files, lock files, and Dockerfiles
- **Download** all GitHub Actions run logs from the exposure window (March 24, 10:00–17:00 UTC) in parallel
- **Detect** compromised versions (v1.82.7/v1.82.8), exfiltration domain IOCs, and `.pth` persistence artifacts
- **Classify** hits as PyPI downloads vs. false positives (Helm chart names, deploy configs, env vars)
- **Report** a per-repo summary with secrets-at-risk assessment

#### [Hardening & Prevention](litellm-hardening-playbook.md)

- **Resolve** the correct safe version to pin based on each repo's existing version specifier (fetches all versions from PyPI API, follows semver)
- **Pin** litellm to an exact version — PyPI files are immutable, so `==` is the primary defense
- **Migrate** from pip to uv or poetry for proper lock file support
- **Remediate** affected environments — delete persistent `litellm_init.pth`, rebuild Docker images

### Usage

#### Detection — paste this prompt to your agent:

```
Run the LiteLLM supply chain compromise detection playbook against our
GitHub org. Search for all litellm references, download workflow logs
from the exposure window, check for compromised versions and IOCs,
and report findings.
```

#### Hardening — paste this prompt to your agent:

```
Follow the LiteLLM hardening playbook to secure our Python dependencies.
Resolve safe versions based on existing specifiers, pin all litellm
references to exact versions, and migrate from pip to uv or poetry
where applicable.
```

---

## About

Created by [Legit Security](https://www.legitsecurity.com) — protecting your software supply chain from code to cloud.

## License

MIT
