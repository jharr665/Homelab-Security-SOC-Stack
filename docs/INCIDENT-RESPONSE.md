# Incident Response Playbook

1. **Detection**
   - Alert from Wazuh/Falco/Suricata triggers incident.
2. **Triage**
   - Validate alert context in Kibana/Grafana.
   - Determine scope (isolated pod, node, or external).
3. **Containment**
   - Quarantine affected workload/VM.
   - Update firewall blocklists (CrowdSec/OPNsense).
4. **Eradication**
   - Remove malicious workload or restore from clean snapshot.
5. **Recovery**
   - Re-enable service from known-good state.
   - Verify patch/vulnerability fix applied.
6. **Postmortem**
   - Document in runbook.
   - Update detections to prevent recurrence.
