# Logging & Alerting Pipeline

- **Falco → Loki**: anomaly logs visible in Grafana dashboards.
- **Kyverno → Prometheus**: metrics on policy violations.
- **Wazuh → Elastic**: log correlation, dashboards, MITRE mapping.
- **Security Onion → Elastic**: Zeek + Suricata logs + packet captures.
- **CrowdSec → OPNsense**: IP blocklists fed directly into firewall rules.
- **Alert Routing**: All critical alerts sent via webhook to Slack/Discord channel.
