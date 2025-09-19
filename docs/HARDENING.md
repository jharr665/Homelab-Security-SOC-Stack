# Hardening Guide

- Deploy Wazuh agents as DaemonSet with minimal privileges.
- Kyverno baseline policies:
  - No containers running as root
  - Mandatory probes
  - Block privileged escalation
  - Enforce resource requests/limits
- Falco tuned ruleset: suppress noise, focus on MITRE ATT&CK TTPs.
- Run Security Onion on a dedicated VLAN with mirrored TAP/SPAN traffic.
- Use API tokens with short TTLs.
