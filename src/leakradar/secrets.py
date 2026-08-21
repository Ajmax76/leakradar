import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Set


@dataclass
class SecretFinding:
    rule_name: str
    matched_path: str
    sample_value: str
    severity: str  # "HIGH" | "CRITICAL"


class SecretDetector:
    PATTERNS: Dict[str, re.Pattern] = {
        "AWS Access Key": re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
        "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
        "Stripe Live Secret Key": re.compile(r"\bsk_live_[0-9a-zA-Z]{24,34}\b"),
        "GitHub Personal Access Token": re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"),
        "Generic Private Key": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
        "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    }

    KEY_NAME_BLACKLIST: Set[str] = {
        "api_key", "apikey", "secret", "client_secret", "private_key",
        "access_token", "auth_token", "passwd", "password"
    }

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        char_counts: Dict[str, int] = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        for count in char_counts.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return entropy

    @classmethod
    def scan_payload(cls, data: Any, prefix: str = "$") -> List[SecretFinding]:
        findings: List[SecretFinding] = []

        if isinstance(data, dict):
            for k, v in data.items():
                curr_path = f"{prefix}.{k}"
                k_lower = str(k).lower()

                # Check if field name explicitly indicates a secret
                if any(blacklisted in k_lower for blacklisted in cls.KEY_NAME_BLACKLIST):
                    if isinstance(v, (str, int)) and str(v).strip():
                        findings.append(
                            SecretFinding(
                                rule_name=f"Sensitive Key Name ('{k}')",
                                matched_path=curr_path,
                                sample_value=str(v)[:4] + "..." + str(v)[-4:] if len(str(v)) > 8 else "***",
                                severity="HIGH",
                            )
                        )

                if isinstance(v, (dict, list)):
                    findings.extend(cls.scan_payload(v, curr_path))
                elif isinstance(v, str):
                    findings.extend(cls._inspect_string(v, curr_path))

        elif isinstance(data, list):
            for idx, item in enumerate(data):
                curr_path = f"{prefix}[{idx}]"
                findings.extend(cls.scan_payload(item, curr_path))

        elif isinstance(data, str):
            findings.extend(cls._inspect_string(data, prefix))

        return findings

    @classmethod
    def _inspect_string(cls, value: str, path: str) -> List[SecretFinding]:
        results: List[SecretFinding] = []
        val_clean = value.strip()

        # 1. Regex Pattern Matches
        for rule, pattern in cls.PATTERNS.items():
            if pattern.search(val_clean):
                results.append(
                    SecretFinding(
                        rule_name=rule,
                        matched_path=path,
                        sample_value=val_clean[:4] + "..." + val_clean[-4:] if len(val_clean) > 8 else "***",
                        severity="CRITICAL",
                    )
                )

        # 2. High Entropy Analysis on alphanumeric tokens (length between 32 and 128)
        if 32 <= len(val_clean) <= 128 and " " not in val_clean:
            entropy = cls.calculate_shannon_entropy(val_clean)
            if entropy >= 4.5:
                results.append(
                    SecretFinding(
                        rule_name=f"High-Entropy Secret (Entropy: {entropy:.2f})",
                        matched_path=path,
                        sample_value=val_clean[:4] + "..." + val_clean[-4:],
                        severity="HIGH",
                    )
                )

        return results
