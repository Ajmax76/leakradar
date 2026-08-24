import json
from typing import List, Optional

from leakradar.bola_matrix import Finding
from leakradar.redactor import Redactor


class MarkdownPoCExporter:
    """
    Exports a BOLA Finding into a professional Markdown proof-of-concept report.
    """

    @classmethod
    def export(cls, finding: Finding, target_name: str = "API Target", custom_tokens: Optional[List[str]] = None) -> str:
        # Sanitize payloads and parameters
        baseline_clean = Redactor.sanitize(finding.baseline_representative, custom_tokens)
        probe_clean = Redactor.sanitize(finding.probe_response, custom_tokens)
        curl_cmd = Redactor.redact_string(finding.to_curl(), custom_tokens)

        # Build evidence table rows
        evidence_rows = []
        if finding.evidence_fields:
            for ev in finding.evidence_fields:
                ev_type = str(ev.get("type", "Signal"))
                ev_field = str(ev.get("field", "N/A"))
                ev_val = Redactor.redact_string(str(ev.get("value", "N/A")), custom_tokens)
                ev_desc = Redactor.redact_string(str(ev.get("description", "")), custom_tokens)
                evidence_rows.append(f"| `{ev_field}` | {ev_type} | `{ev_val}` | {ev_desc} |")
        else:
            evidence_rows.append(
                f"| `$` | High Data Overlap | `{finding.overlap_score * 100:.1f}%` | User B accessed User A resource with {finding.overlap_score * 100:.1f}% field overlap. |"
            )

        evidence_table = "\n".join(evidence_rows)

        baseline_json_str = json.dumps(baseline_clean, indent=2) if baseline_clean is not None else "{}"
        probe_json_str = json.dumps(probe_clean, indent=2) if probe_clean is not None else "{}"

        md_template = f"""# [Vulnerability Report] Broken Object Level Authorization (BOLA/IDOR) on {finding.seed.endpoint_template}

## Executive Summary
- **Target System:** {target_name}
- **Vulnerable Endpoint:** `{finding.seed.endpoint_template}`
- **HTTP Method:** `{finding.probe_method}`
- **Severity / Confidence:** `{finding.confidence.upper()}` Confidence BOLA
- **CVSS Score:** `{finding.cvss_suggestion}`
- **CWE:** `{finding.cwe_suggestion}`

LeakRadar detected that User B (Attacker) successfully accessed resources belonging to User A (Victim) without proper authorization checks.

---

## Findings & Evidence Matrix

| Path / Field | Evidence Type | Exposed Value | Description |
|---|---|---|---|
{evidence_table}

- **Field Overlap Score:** `{finding.overlap_score * 100:.1f}%`
- **Probe Status Code:** `{finding.probe_status_code}`

---

## Proof of Concept & Reproduction Steps

1. Authenticate as **User B** (Low Privilege / Attacker).
2. Execute the following cURL request targeted at User A's resource:

```bash
{curl_cmd}
```

---

## Payload Comparison

### User A (Baseline Owner Response)
```json
{baseline_json_str}
```

### User B (Unauthorized Probe Response)
```json
{probe_json_str}
```

---

## Impact
An authenticated user can bypass access controls by tampering with object identifiers in API requests. This leads to unauthorized disclosure of sensitive data, violation of user privacy, and potential regulatory non-compliance (GDPR/HIPAA).

---

## Remediation Guidance
1. **Implement Object-Level Authorization Checks:** Verify that the authenticated user initiating the request owns or has explicit permission to access the requested resource.
2. **Use Indirect Object References:** Implement random UUIDs or session-bound tokens instead of sequential or predictable identifiers.
3. **Enforce Centralized Access Control Policies:** Delegate authorization checks to a centralized policy enforcement point (e.g., OAuth scopes / ABAC).
"""
        return md_template
