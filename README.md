# Homelab Security & SOC Stack — Detection, Response, & Hardening

> Wazuh SIEM/XDR • Security Onion (Suricata, Zeek, Elastic) • Falco • CrowdSec • Kyverno • Trivy Operator • Threat Intel (MISP, TheHive, Cortex)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#license)
![Focus](https://img.shields.io/badge/Focus-SIEM,_IDS,_SOC-blue)
![Platform](https://img.shields.io/badge/Platform-Kubernetes_+_VMs-orange)

This repo holds the **defensive operations stack** of the homelab. It provides **centralized log collection, intrusion detection, runtime monitoring, and compliance scanning** — a mini Security Operations Center (SOC) built from open-source tools.

---

## ✨ Highlights
- **Wazuh SIEM/XDR** (log analysis, FIM, vulnerability detection, agent-based)
- **Security Onion VM** (Suricata IDS, Zeek network monitoring, Elastic dashboards)
- **Falco** for container runtime anomaly detection
- **CrowdSec** for collaborative IP reputation & blocking
- **Kyverno** for Kubernetes policy enforcement
- **Trivy Operator** for cluster-wide CVE/compliance scanning
- **Threat Intel**: optional MISP + TheHive + Cortex

---

## 🧭 High-Level Architecture

```mermaid
flowchart LR
  subgraph K8s["Kubernetes Cluster"]
    Falco
    Kyverno
    Trivy[Trivy Operator]
    CrowdSec
    WazuhAgents[Wazuh Agents (DaemonSet)]
  end

  subgraph VMs
    SO[Security Onion VM]
    WazuhMgr[Wazuh Manager]
  end

  Falco --> Logs
  Kyverno --> Logs
  Trivy --> Logs
  CrowdSec --> Logs
  WazuhAgents --> WazuhMgr
  SO --> Elastic[(Elastic/Kibana)]
  WazuhMgr --> Kibana
```

---

## 📁 Repo Layout
```
security-soc-stack/
├─ README.md
├─ .env.example
├─ kubernetes/
│  ├─ wazuh/
│  ├─ falco/
│  ├─ crowdsec/
│  ├─ kyverno/
│  └─ trivy-operator/
├─ vm/security-onion/
│  └─ README.md
├─ docs/
│  ├─ ARCHITECTURE.md
│  ├─ HARDENING.md
│  ├─ INCIDENT-RESPONSE.md
│  ├─ THREAT-INTEL.md
│  └─ LOGGING-PIPELINE.md
└─ .gitignore
```

---

## 🚀 Quick Start

### Deploy in Kubernetes
```bash
helm upgrade --install wazuh wazuh/wazuh -f kubernetes/wazuh/values.yaml
helm upgrade --install falco falcosecurity/falco -f kubernetes/falco/values.yaml
helm upgrade --install crowdsec crowdsec/crowdsec -f kubernetes/crowdsec/values.yaml
helm upgrade --install kyverno kyverno/kyverno -f kubernetes/kyverno/values.yaml
helm upgrade --install trivy trivy-operator/trivy-operator -f kubernetes/trivy-operator/values.yaml
```

### Security Onion VM
- Deploy Security Onion on a dedicated Proxmox VM.
- Connect mirrored VLAN/SPAN port for IDS traffic.
- Use Zeek/Suricata for packet analysis, Elastic dashboards for threat hunting.

---

## 🔐 Security Controls

- **Wazuh**: file integrity monitoring, vuln detection, rootkit detection, MITRE ATT&CK mapping
- **Falco**: suspicious syscalls, container escapes, crypto miners
- **CrowdSec**: shared IP reputation, auto-bans
- **Kyverno**: enforce CIS baseline, block privileged containers
- **Trivy Operator**: ongoing workload CVE scans
- **Security Onion**: deep packet inspection + Zeek logs

---

## 📊 Monitoring Hooks
- Wazuh alerts → Elastic/Kibana
- Falco → Loki/Grafana dashboards
- CrowdSec decisions → OPNsense firewall blocklists
- Kyverno violations → Prometheus metrics
- Trivy results → compliance scorecards

---

## 📌 Roadmap
- Automate SO VM provisioning with cloud-init
- Add MISP + TheHive + Cortex integration
- Add Sigma rule-to-Wazuh pipeline
- Wire SOC alerts into Slack/Discord via webhooks

---

## 📝 License
MIT — see `LICENSE`
