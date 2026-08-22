import hashlib
import json
import re

def normalize_value(val):
    """
    Recursively normalize JSON values:
    - Trim whitespace on strings.
    - Coerce boolean strings ("true"/"false") to bool.
    - Preserve numeric strings (keep leading zeros).
    - Sort dict keys alphabetically.
    - Recursively normalize list elements.
    - Return None for None, empty string, empty dict, or empty list.
    """
    if val is None:
        return None

    if isinstance(val, bool):
        return val

    if isinstance(val, (int, float)):
        return val

    if isinstance(val, str):
        cleaned = val.strip()
        if not cleaned:
            return None
        lowered = cleaned.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        return cleaned

    if isinstance(val, dict):
        normalized_dict = {}
        for k in sorted(val.keys()):
            norm_k = str(k).strip()
            norm_v = normalize_value(val[k])
            if norm_v is not None:
                normalized_dict[norm_k] = norm_v
        if not normalized_dict:
            return None
        return normalized_dict

    if isinstance(val, list):
        normalized_list = []
        for item in val:
            norm_item = normalize_value(item)
            if norm_item is not None:
                normalized_list.append(norm_item)
        if not normalized_list:
            return None
        return normalized_list

    return val


def _find_stable_id_key(obj_list):
    """
    Given a list of dicts, find a common key that serves as a stable identifier.
    Priority: id, uuid, _id, uid, key, slug, code, identifier, then keys ending in _id or id/Id/-id.
    Must be scalar (str, int, float, bool) in all dicts containing it.
    """
    if not obj_list or not all(isinstance(x, dict) for x in obj_list):
        return None

    priority_candidates = ["id", "uuid", "_id", "uid", "key", "slug", "code", "identifier"]
    all_keys = set()
    for item in obj_list:
        all_keys.update(item.keys())

    # Check priority candidates first
    for cand in priority_candidates:
        if cand in all_keys:
            if all(cand in item and isinstance(item[cand], (str, int, float)) for item in obj_list):
                return cand

    # Check keys ending with _id, id, -id, Id
    suffix_candidates = [
        k for k in sorted(all_keys)
        if k.endswith("_id") or k.endswith("-id") or k.endswith("Id") or (len(k) > 2 and k.endswith("id"))
    ]
    for cand in suffix_candidates:
        if cand not in priority_candidates:
            if all(cand in item and isinstance(item[cand], (str, int, float)) for item in obj_list):
                return cand

    return None


def _diff_two_structures(d1, d2, prefix="$"):
    """
    Recursively compare two normalized structures and return a set of JSONPath-like strings where values differ.
    Always returns a set.
    """
    volatile = set()

    if d1 is None and d2 is None:
        return volatile

    if d1 is None or d2 is None or type(d1) != type(d2):
        volatile.add(prefix)
        return volatile

    if isinstance(d1, dict):
        all_keys = set(d1.keys()).union(set(d2.keys()))
        for k in all_keys:
            child_prefix = f"{prefix}.{k}"
            v1 = d1.get(k)
            v2 = d2.get(k)
            volatile.update(_diff_two_structures(v1, v2, child_prefix))
        return volatile

    if isinstance(d1, list):
        if not d1 and not d2:
            return volatile
        
        # Primitive array check
        if all(isinstance(x, (str, int, float, bool)) for x in d1 + d2):
            if set(d1) != set(d2):
                volatile.add(f"{prefix}[*]")
            return volatile

        # List of dicts check
        if all(isinstance(x, dict) for x in d1) and all(isinstance(x, dict) for x in d2):
            stable_key = _find_stable_id_key(d1 + d2)
            if stable_key:
                d1_map = {x[stable_key]: x for x in d1 if stable_key in x}
                d2_map = {x[stable_key]: x for x in d2 if stable_key in x}
                
                # Check if all elements have stable_key
                if len(d1_map) == len(d1) and len(d2_map) == len(d2):
                    common_ids = set(d1_map.keys()).intersection(set(d2_map.keys()))
                    if len(common_ids) != len(d1_map) or len(common_ids) != len(d2_map):
                        volatile.add(f"{prefix}[*]")
                    
                    for cid in common_ids:
                        volatile.update(_diff_two_structures(d1_map[cid], d2_map[cid], f"{prefix}[*]"))
                    return volatile

            # Fallback for list of dicts without common stable key or missing IDs
            volatile.add(f"{prefix}[*]")
            return volatile

        # Fallback index comparison for mixed list
        max_len = max(len(d1), len(d2))
        for i in range(max_len):
            v1 = d1[i] if i < len(d1) else None
            v2 = d2[i] if i < len(d2) else None
            volatile.update(_diff_two_structures(v1, v2, f"{prefix}[*]"))
        return volatile

    # Scalar comparison
    if d1 != d2:
        volatile.add(prefix)

    return volatile


def extract_volatile_paths(resp1, resp2, resp3):
    """
    Compute pairwise diffs (1-2, 2-3, 1-3) across 3 normalized responses and return union of volatile paths.
    """
    n1 = normalize_value(resp1)
    n2 = normalize_value(resp2)
    n3 = normalize_value(resp3)

    diff12 = _diff_two_structures(n1, n2)
    diff23 = _diff_two_structures(n2, n3)
    diff13 = _diff_two_structures(n1, n3)

    return diff12.union(diff23).union(diff13)


def _matches_volatile_path(current_path, volatile_paths):
    """
    Check if current_path matches any path in volatile_paths (supporting [*] wildcards).
    """
    if current_path in volatile_paths:
        return True

    # Convert wildcard path to regex
    for vpath in volatile_paths:
        pattern = "^" + re.escape(vpath).replace(r"\[\*\]", r"\[\d+\]").replace(r"\[\*\]", r"\[.*?\]") + "$"
        # Also handle exact match replacing [*] with standard matching
        regex_pat = "^" + re.escape(vpath).replace(r"\[\*\]", r"(\[\d+\]|\[\*\])") + "$"
        if re.match(regex_pat, current_path):
            return True

    return False


def strip_paths(data, paths_to_remove, prefix="$"):
    """
    Recursively remove fields matching volatile paths.
    """
    if data is None or not paths_to_remove:
        return data

    if _matches_volatile_path(prefix, paths_to_remove):
        return None

    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            child_prefix = f"{prefix}.{k}"
            if not _matches_volatile_path(child_prefix, paths_to_remove):
                stripped_v = strip_paths(v, paths_to_remove, child_prefix)
                if stripped_v is not None:
                    result[k] = stripped_v
        return result if result else None

    if isinstance(data, list):
        result = []
        for i, item in enumerate(data):
            child_prefix = f"{prefix}[*]"
            if not _matches_volatile_path(child_prefix, paths_to_remove):
                stripped_item = strip_paths(item, paths_to_remove, child_prefix)
                if stripped_item is not None:
                    result.append(stripped_item)
        return result if result else None

    return data


def compute_canonical_hash(data, volatile_paths=None):
    """
    Normalize data, strip volatile paths if provided, sort lists deterministically by SHA-256,
    and return SHA-256 of resulting JSON string.
    """
    norm = normalize_value(data)
    if volatile_paths:
        norm = strip_paths(norm, volatile_paths)

    def sort_recursive(val):
        if isinstance(val, dict):
            return {k: sort_recursive(val[k]) for k in sorted(val.keys())}
        if isinstance(val, list):
            sorted_items = [sort_recursive(x) for x in val]
            return sorted(
                sorted_items,
                key=lambda x: hashlib.sha256(json.dumps(x, sort_keys=True).encode("utf-8")).hexdigest()
            )
        return val

    sorted_norm = sort_recursive(norm)
    json_str = json.dumps(sorted_norm, sort_keys=True)
    return hashlib.sha256(json_str.encode("utf-8")).hexdigest()


class ErrorDetector:
    """
    Detects if a response status code or body represents an error response.
    """

    ERROR_STATUS_CODES = {401, 403, 404, 405, 429, 500, 502, 503}
    ERROR_SNIPPETS = {
        "unauthorized", "denied", "forbidden", "not found", "invalid token",
        "permission", "access denied", "authentication failed", "not allowed",
        "error", "exception", "failed"
    }

    @classmethod
    def is_error_payload(cls, status_code: int, raw_data) -> tuple[bool, str]:
        """
        Returns (is_error, reason).
        """
        if status_code in cls.ERROR_STATUS_CODES:
            return True, f"HTTP Error Status Code: {status_code}"

        if status_code >= 400:
            return True, f"HTTP Error Status Code >= 400: {status_code}"

        if raw_data is None or raw_data == "":
            return True, "Empty Body"

        norm_data = normalize_value(raw_data)
        if norm_data is None:
            return True, "Empty Normalized Payload"

        # Check bool status/success flags
        if isinstance(norm_data, dict):
            if norm_data.get("success") is False:
                return True, "Flag success=false"
            if norm_data.get("status") is False or str(norm_data.get("status")).lower() == "error":
                return True, "Flag status=false/error"
            if norm_data.get("error") is True or "error" in norm_data:
                err_val = norm_data.get("error")
                if err_val not in (None, False, [], {}):
                    return True, f"Explicit error field present: {err_val}"
            if "errors" in norm_data and isinstance(norm_data["errors"], list) and len(norm_data["errors"]) > 0:
                return True, "Non-empty errors list"

            # Check small dict error payload
            if len(norm_data) <= 4:
                error_keys = {"error", "message", "msg", "detail", "code", "description", "title"}
                dict_keys = set(norm_data.keys())
                if dict_keys.intersection(error_keys):
                    for k in dict_keys.intersection(error_keys):
                        val_str = str(norm_data[k]).lower()
                        if any(snip in val_str for snip in cls.ERROR_SNIPPETS):
                            return True, f"Small dict with error message key '{k}': {norm_data[k]}"

        # Check raw text for snippet match
        if isinstance(raw_data, str):
            lowered = raw_data.lower()
            for snip in cls.ERROR_SNIPPETS:
                if snip in lowered:
                    return True, f"Error snippet found in text: '{snip}'"

        return False, "Valid response"
