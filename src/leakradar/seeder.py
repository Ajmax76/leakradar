import base64
import itertools
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
import httpx

from leakradar.canonicalizer import ErrorDetector, extract_volatile_paths


@dataclass
class ResourceSeed:
    base_url: str
    method: str
    endpoint_template: str
    param_values: Dict[str, Any]
    id_location: str = "path"
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, Any] = field(default_factory=dict)
    body_template: Optional[Dict[str, Any]] = None
    baseline_responses: List[Any] = field(default_factory=list)
    volatile_paths: Set[str] = field(default_factory=set)


@dataclass
class SeedResult:
    resources: List[ResourceSeed] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class JWTClaimHarvester:
    """
    Decodes JWT Bearer tokens to extract claims into parameter pools.
    """

    CLAIM_MAPPINGS = {
        "sub": ["sub", "user_id", "userid", "id", "account_id"],
        "user_id": ["user_id", "userid", "id"],
        "username": ["username", "user", "name"],
        "email": ["email"],
        "account_id": ["account_id", "accountid", "account"],
        "tenant_id": ["tenant_id", "tenantid", "tenant"],
        "org_id": ["org_id", "orgid", "organization_id"],
        "customer_id": ["customer_id", "customerid"],
    }

    @classmethod
    def harvest_from_headers(cls, headers: Dict[str, str]) -> Dict[str, List[Any]]:
        param_pool: Dict[str, List[Any]] = {}
        auth_header = headers.get("Authorization") or headers.get("authorization") or ""
        
        if not auth_header.startswith("Bearer "):
            return param_pool

        token = auth_header.split(" ", 1)[1].strip()
        parts = token.split(".")
        if len(parts) != 3:
            return param_pool

        try:
            # Base64 decode payload
            payload_b64 = parts[1]
            # Fix padding
            payload_b64 += "=" * (-len(payload_b64) % 4)
            decoded_bytes = base64.urlsafe_b64decode(payload_b64)
            claims = json.loads(decoded_bytes.decode("utf-8"))

            if isinstance(claims, dict):
                for claim_key, claim_val in claims.items():
                    if isinstance(claim_val, (str, int, float)) and claim_val:
                        aliases = cls.CLAIM_MAPPINGS.get(claim_key.lower(), [claim_key.lower()])
                        for alias in aliases:
                            if alias not in param_pool:
                                param_pool[alias] = []
                            if claim_val not in param_pool[alias]:
                                param_pool[alias].append(claim_val)
        except Exception:
            pass

        return param_pool


class ParamMatcher:
    """
    Matches OpenAPI path parameter names against populated parameter pool values.
    """

    @classmethod
    def find_matching_values(cls, param_name: str, param_pool: Dict[str, List[Any]]) -> List[Any]:
        norm_name = re.sub(r"[_\-]", "", param_name.lower())

        # Exact match
        if param_name.lower() in param_pool:
            return param_pool[param_name.lower()]

        # Normalized match
        for key, values in param_pool.items():
            norm_key = re.sub(r"[_\-]", "", key.lower())
            if norm_name == norm_key:
                return values

        # Substring / Alias match
        for key, values in param_pool.items():
            norm_key = re.sub(r"[_\-]", "", key.lower())
            if norm_name in norm_key or norm_key in norm_name:
                return values

        # Generic "id" fallback match
        if "id" in param_pool and ("id" in norm_name or norm_name == "id"):
            return param_pool["id"]
        if "user_id" in param_pool and "user" in norm_name:
            return param_pool["user_id"]

        return []


class ResourceHarvester:
    """
    Extracts candidate resource IDs from API responses.
    """

    EXCLUDE_KEYWORDS = {
        "time", "timestamp", "date", "created", "updated", "nonce", "hash",
        "signature", "token", "auth", "name", "description", "title", "status",
        "page", "limit", "total", "count", "version", "success", "error", "message"
    }

    WRAPPER_KEYS = ["data", "items", "results", "content", "payload", "records", "list"]

    @classmethod
    def unwrap_payload(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for key in cls.WRAPPER_KEYS:
                if key in data and isinstance(data[key], (list, dict)):
                    return cls.unwrap_payload(data[key])
        return data

    @classmethod
    def score_field_name(cls, field_name: str, path_hint: str = "") -> int:
        fname = field_name.lower()
        if any(ex in fname for ex in cls.EXCLUDE_KEYWORDS):
            return -100

        score = 0
        if fname == "id" or fname == "uuid" or fname == "guid":
            score += 50
        elif fname.endswith("_id") or fname.endswith("-id") or fname.endswith("Id"):
            score += 40
        elif "id" in fname:
            score += 20

        if path_hint and path_hint.lower() in fname:
            score += 30

        return score

    @classmethod
    def extract_ids(cls, raw_payload: Any, path_hint: str = "") -> Dict[str, List[Any]]:
        extracted: Dict[str, List[Any]] = {}
        unwrapped = cls.unwrap_payload(raw_payload)

        items = []
        if isinstance(unwrapped, list):
            items = unwrapped
        elif isinstance(unwrapped, dict):
            items = [unwrapped]

        for item in items:
            if not isinstance(item, dict):
                continue
            for field_name, val in item.items():
                if isinstance(val, (str, int)) and val:
                    val_str = str(val).strip()
                    if val_str and len(val_str) < 128:
                        score = cls.score_field_name(field_name, path_hint)
                        if score > 0:
                            key_name = field_name.lower()
                            if key_name not in extracted:
                                extracted[key_name] = []
                            if val not in extracted[key_name]:
                                extracted[key_name].append(val)

        return extracted


class OpenAPISeeder:
    """
    Discovers resource IDs and builds ResourceSeed instances from OpenAPI specs.
    """

    def __init__(self, base_url: str, user_a_headers: Dict[str, str], client: Optional[httpx.Client] = None):
        self.base_url = base_url.rstrip("/")
        self.user_a_headers = user_a_headers
        self.client = client or httpx.Client(timeout=10.0, follow_redirects=True)
        self.param_pool: Dict[str, List[Any]] = JWTClaimHarvester.harvest_from_headers(user_a_headers)

    def _extract_path_params(self, path: str) -> List[str]:
        return re.findall(r"\{([^}]+)\}", path)

    def _build_url(self, template: str, params: Dict[str, Any]) -> str:
        url = template
        for k, v in params.items():
            url = url.replace(f"{{{k}}}", str(v))
        return f"{self.base_url}{url}"

    def _fetch_baseline_triplet(self, url: str) -> Tuple[bool, List[Any], Set[str]]:
        responses = []
        for _ in range(3):
            try:
                resp = self.client.get(url, headers=self.user_a_headers)
                is_err, _ = ErrorDetector.is_error_payload(resp.status_code, resp.text)
                if is_err:
                    return False, [], set()
                try:
                    data = resp.json()
                except Exception:
                    return False, [], set()
                responses.append(data)
            except Exception:
                return False, [], set()

        if len(responses) < 3:
            return False, [], set()

        volatile_paths = extract_volatile_paths(responses[0], responses[1], responses[2])
        return True, responses, volatile_paths

    def seed_endpoints(self, openapi_paths: Dict[str, Any]) -> SeedResult:
        result = SeedResult()

        # Filter only GET endpoints
        get_endpoints = []
        for path, path_obj in openapi_paths.items():
            if isinstance(path_obj, dict) and "get" in path_obj:
                get_endpoints.append(path)

        # Sort by number of path parameters ascending (0-param GET paths first)
        get_endpoints.sort(key=lambda p: len(self._extract_path_params(p)))

        for path in get_endpoints:
            params = self._extract_path_params(path)
            path_hint = path.strip("/").split("/")[0] if path.strip("/") else "resource"

            if len(params) == 0:
                full_url = self._build_url(path, {})
                success, baselines, volatile = self._fetch_baseline_triplet(full_url)
                if success and baselines:
                    # Extract IDs into param pool
                    extracted_ids = ResourceHarvester.extract_ids(baselines[0], path_hint)
                    for key_name, vals in extracted_ids.items():
                        if key_name not in self.param_pool:
                            self.param_pool[key_name] = []
                        for v in vals:
                            if v not in self.param_pool[key_name]:
                                self.param_pool[key_name].append(v)
                    # Add path hint alias
                    alias_key = f"{path_hint}_id".lower()
                    if alias_key not in self.param_pool and extracted_ids:
                        first_list = next(iter(extracted_ids.values()))
                        self.param_pool[alias_key] = first_list

                    seed = ResourceSeed(
                        base_url=self.base_url,
                        method="GET",
                        endpoint_template=path,
                        param_values={},
                        headers=self.user_a_headers,
                        baseline_responses=baselines,
                        volatile_paths=volatile,
                    )
                    result.resources.append(seed)
                else:
                    result.warnings.append(f"Could not fetch 3 clean baseline responses for {path}")

            else:
                # Parameterized path
                param_value_options: Dict[str, List[Any]] = {}
                missing_params = []

                for p in params:
                    vals = ParamMatcher.find_matching_values(p, self.param_pool)
                    if vals:
                        param_value_options[p] = vals[:3]  # Limit up to 3 values per param
                    else:
                        missing_params.append(p)

                if missing_params:
                    result.warnings.append(
                        f"Skipping parameterized endpoint {path}: missing pool values for params {missing_params}"
                    )
                    continue

                # Cartesian product of parameter options
                keys = list(param_value_options.keys())
                value_combinations = list(itertools.product(*(param_value_options[k] for k in keys)))

                for combo in value_combinations:
                    param_dict = dict(zip(keys, combo))
                    full_url = self._build_url(path, param_dict)
                    success, baselines, volatile = self._fetch_baseline_triplet(full_url)
                    if success and baselines:
                        # Extract child IDs into pool
                        extracted_ids = ResourceHarvester.extract_ids(baselines[0], path_hint)
                        for key_name, vals in extracted_ids.items():
                            if key_name not in self.param_pool:
                                self.param_pool[key_name] = []
                            for v in vals:
                                if v not in self.param_pool[key_name]:
                                    self.param_pool[key_name].append(v)

                        seed = ResourceSeed(
                            base_url=self.base_url,
                            method="GET",
                            endpoint_template=path,
                            param_values=param_dict,
                            headers=self.user_a_headers,
                            baseline_responses=baselines,
                            volatile_paths=volatile,
                        )
                        result.resources.append(seed)

        return result
