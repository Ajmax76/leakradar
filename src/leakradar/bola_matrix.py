from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
import httpx

from leakradar.canonicalizer import ErrorDetector, normalize_value, strip_paths
from leakradar.seeder import ResourceSeed, SeedResult
from leakradar.secrets import SecretDetector, SecretFinding

ID_FIELD_EXACT = {"id", "uuid", "guid", "key", "slug", "code", "identifier"}
ID_FIELD_SUFFIXES = ("_id", "-id", "Id")


def is_id_field(field_name: str) -> bool:
    """
    Check if a field name is an ID field using exact matches or specific suffixes.
    Prevents broad matches on words like 'valid' or 'solid'.
    """
    fname = field_name.strip()
    if fname in ID_FIELD_EXACT:
        return True
    for suff in ID_FIELD_SUFFIXES:
        if fname.endswith(suff):
            return True
    return False


@dataclass
class Finding:
    seed: ResourceSeed
    probe_url: str
    probe_method: str
    probe_status_code: int
    confidence: str  # "high" | "medium" | "low"
    evidence_fields: List[Dict[str, Any]]
    overlap_score: float
    baseline_representative: Any
    probe_response: Any
    cvss_suggestion: str = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (7.5 High)"
    cwe_suggestion: str = "CWE-639: Authorization Bypass Through User-Controlled Key"
    secret_findings: List[SecretFinding] = field(default_factory=list)

    def to_curl(self) -> str:
        headers_str = " \\\n  ".join(
            f'-H "{k}: <REDACTED_USER_B_TOKEN>"' if k.lower() == "authorization" else f'-H "{k}: {v}"'
            for k, v in self.seed.headers.items()
        )
        if headers_str:
            return f"curl -X {self.probe_method} \"{self.probe_url}\" \\\n  {headers_str}"
        return f"curl -X {self.probe_method} \"{self.probe_url}\""


class IdentityExtractor:
    """
    Flattens payload structures into scalar leaf maps and extracts identity ownership values.
    """

    OWNERSHIP_FIELDS = {
        "user_id", "owner_id", "created_by", "customer_id", "account_id",
        "tenant_id", "email", "username", "sub", "author_id", "creator_id"
    }

    @classmethod
    def get_scalar_leaf_map(cls, data: Any, prefix: str = "$") -> Dict[str, Any]:
        leaf_map: Dict[str, Any] = {}

        if data is None:
            return leaf_map

        if isinstance(data, (str, int, float, bool)):
            leaf_map[prefix] = data
            return leaf_map

        if isinstance(data, dict):
            for k, v in data.items():
                child_prefix = f"{prefix}.{k}"
                leaf_map.update(cls.get_scalar_leaf_map(v, child_prefix))
            return leaf_map

        if isinstance(data, list):
            for i, item in enumerate(data):
                child_prefix = f"{prefix}[*]"
                leaf_map.update(cls.get_scalar_leaf_map(item, child_prefix))
            return leaf_map

        return leaf_map

    @classmethod
    def extract_identity_values(cls, baseline: Any, seed: ResourceSeed) -> Dict[str, Any]:
        identity_map: Dict[str, Any] = {}

        # Include seed path parameter values
        for param_k, param_v in seed.param_values.items():
            identity_map[f"$.param.{param_k}"] = param_v

        # Traverse baseline payload for ownership fields
        leaf_map = cls.get_scalar_leaf_map(baseline)
        for path, val in leaf_map.items():
            field_name = path.split(".")[-1].split("[")[0].lower()
            if field_name in cls.OWNERSHIP_FIELDS or is_id_field(field_name):
                identity_map[path] = val

        return identity_map


class BolaMatrixRunner:
    """
    Executes cross-token replay with User B credentials and classifies BOLA findings.
    """

    def __init__(
        self,
        user_b_headers: Dict[str, str],
        client: Optional[httpx.Client] = None,
        allow_destructive: bool = False,
    ):
        self.user_b_headers = user_b_headers
        self.client = client or httpx.Client(timeout=10.0, follow_redirects=True)
        self.allow_destructive = allow_destructive

    def _build_probe_url(self, seed: ResourceSeed) -> str:
        url = seed.endpoint_template
        for k, v in seed.param_values.items():
            url = url.replace(f"{{{k}}}", str(v))
        full_url = f"{seed.base_url.rstrip('/')}{url}"
        if seed.query_params:
            from urllib.parse import urlencode
            query_str = urlencode(seed.query_params)
            full_url = f"{full_url}?{query_str}"
        return full_url

    def _send_probe(self, method: str, url: str) -> Tuple[int, Any]:
        try:
            resp = self.client.request(method, url, headers=self.user_b_headers)
            try:
                data = resp.json()
            except Exception:
                data = resp.text
            return resp.status_code, data
        except Exception as e:
            return 500, str(e)

    def _classify(
        self,
        baseline_stripped: Any,
        probe_stripped: Any,
        identity_map: Dict[str, Any],
        seed: ResourceSeed,
        status_code: int,
    ) -> Tuple[str, List[Dict[str, Any]], float]:
        """
        Classifies confidence (high, medium, low) and returns (confidence, evidence_list, overlap_score).
        """
        if status_code not in (200, 201, 204):
            return "low", [], 0.0

        is_err, _ = ErrorDetector.is_error_payload(status_code, probe_stripped)
        if is_err:
            return "low", [], 0.0

        base_leaves = IdentityExtractor.get_scalar_leaf_map(baseline_stripped)
        probe_leaves = IdentityExtractor.get_scalar_leaf_map(probe_stripped)

        if not base_leaves or not probe_leaves:
            return "low", [], 0.0

        # Calculate Leaf Overlap
        matching_leaves = 0
        evidence_list = []

        for path, val in base_leaves.items():
            if path in probe_leaves and probe_leaves[path] == val:
                matching_leaves += 1

        overlap_score = matching_leaves / float(len(base_leaves))

        # Signal 1: Resource ID Echoing
        id_echo_signal = False
        for param_k, param_v in seed.param_values.items():
            param_v_str = str(param_v).lower()
            for path, pval in probe_leaves.items():
                field_name = path.split(".")[-1].split("[")[0]
                if is_id_field(field_name) and str(pval).lower() == param_v_str:
                    id_echo_signal = True
                    evidence_list.append({
                        "type": "Resource ID Echo",
                        "field": path,
                        "value": pval,
                        "description": f"Target parameter value '{param_v}' for '{param_k}' echoed in User B response."
                    })
                    break

        # Signal 2: Ownership Field Match
        ownership_match_signal = False
        for id_path, id_val in identity_map.items():
            if id_path.startswith("$.param."):
                continue
            if id_path in probe_leaves and probe_leaves[id_path] == id_val:
                ownership_match_signal = True
                evidence_list.append({
                    "type": "Ownership Data Exposure",
                    "field": id_path,
                    "value": id_val,
                    "description": f"User A ownership field '{id_path}' returned to User B with identical value."
                })

        # General overlap evidence
        if overlap_score >= 0.4:
            evidence_list.append({
                "type": "High Data Overlap",
                "field": "$ (root)",
                "value": f"{overlap_score * 100:.1f}%",
                "description": f"User B response matches {overlap_score * 100:.1f}% of User A baseline fields."
            })

        # Classification Matrix Logic
        if (id_echo_signal and ownership_match_signal) or \
           (id_echo_signal and overlap_score >= 0.3) or \
           (ownership_match_signal and overlap_score >= 0.6) or \
           (overlap_score >= 0.85):
            return "high", evidence_list, overlap_score

        if (id_echo_signal and overlap_score >= 0.2) or \
           ownership_match_signal or \
           (overlap_score >= 0.4):
            return "medium", evidence_list, overlap_score

        return "low", evidence_list, overlap_score

    def run(self, seed_result: SeedResult) -> List[Finding]:
        findings: List[Finding] = []

        for seed in seed_result.resources:
            if not seed.param_values and not seed.query_params:
                continue

            method_upper = seed.method.upper()
            if method_upper not in ("GET", "HEAD") and not self.allow_destructive:
                seed_result.warnings.append(
                    f"Detected state-modifying endpoint {method_upper} {seed.endpoint_template} but skipped probing (safe mode) — re-run with --allow-destructive to test."
                )
                continue

            # Enforce Free Tier Rate Throttling in Core Engine Loop
            from leakradar.auth import LicenseManager
            import time
            lic_ctx = LicenseManager.get_active_context()
            if lic_ctx.tier.lower() == "free":
                time.sleep(1.5)

            probe_url = self._build_probe_url(seed)
            status_code, probe_raw = self._send_probe(seed.method, probe_url)

            # Error check
            is_err, _ = ErrorDetector.is_error_payload(status_code, probe_raw)
            if is_err:
                continue

            baseline_raw = seed.baseline_responses[0] if seed.baseline_responses else {}
            baseline_norm = normalize_value(baseline_raw)
            probe_norm = normalize_value(probe_raw)

            # Scan probe response for exposed secrets and tokens
            detected_secrets = SecretDetector.scan_payload(probe_raw)

            # Strip volatile paths
            baseline_stripped = strip_paths(baseline_norm, seed.volatile_paths)
            probe_stripped = strip_paths(probe_norm, seed.volatile_paths)

            # Extract identity values from User A baseline
            identity_map = IdentityExtractor.extract_identity_values(baseline_norm, seed)

            confidence, evidence, overlap = self._classify(
                baseline_stripped, probe_stripped, identity_map, seed, status_code
            )

            if confidence in ("high", "medium") or detected_secrets:
                findings.append(Finding(
                    seed=seed,
                    probe_url=probe_url,
                    probe_method=seed.method,
                    probe_status_code=status_code,
                    confidence=confidence if confidence in ("high", "medium") else "medium",
                    evidence_fields=evidence,
                    overlap_score=overlap,
                    baseline_representative=baseline_stripped,
                    probe_response=probe_stripped,
                    secret_findings=detected_secrets,
                ))

        return findings
