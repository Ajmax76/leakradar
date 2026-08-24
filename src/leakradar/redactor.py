import re
from typing import Any, List, Optional, Set


class Redactor:
    """
    Redacts sensitive credentials, JWT tokens, PII, and secret fields from text and structured JSON.
    """

    PATTERNS = [
        # JWT Token
        (r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "<REDACTED_JWT_TOKEN>"),
        # Bearer Token
        (r"Bearer\s+[A-Za-z0-9_\-\.\~]+", "Bearer <REDACTED_TOKEN>"),
        # Email address
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "<REDACTED_EMAIL>"),
        # Credit Card (13-19 digits)
        (r"\b(?:\d[ -]*?){13,19}\b", "<REDACTED_CREDIT_CARD>"),
        # AWS Key ID
        (r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "<REDACTED_AWS_KEY>"),
        # Generic Secret / API Key strings
        (r"\b[A-Za-z0-9_-]{32,64}\b", "<REDACTED_SECRET>"),
    ]

    SECRET_KEY_TERMS = {
        "password", "passwd", "secret", "token", "auth", "key", "api_key",
        "apikey", "access_token", "private_key", "credential", "session"
    }

    @classmethod
    def redact_string(cls, text: str, custom_tokens: Optional[List[str]] = None) -> str:
        if not text or not isinstance(text, str):
            return text

        redacted = text

        # Apply custom tokens redaction first
        if custom_tokens:
            for token in custom_tokens:
                if token and len(str(token)) > 2:
                    redacted = redacted.replace(str(token), "<REDACTED_CUSTOM_TOKEN>")

        # Apply regex patterns
        for pattern, replacement in cls.PATTERNS:
            redacted = re.sub(pattern, replacement, redacted)

        return redacted

    @classmethod
    def sanitize(cls, data: Any, custom_tokens: Optional[List[str]] = None) -> Any:
        if data is None:
            return None

        if isinstance(data, str):
            return cls.redact_string(data, custom_tokens)

        if isinstance(data, (int, float, bool)):
            if custom_tokens and str(data) in custom_tokens:
                return "<REDACTED_CUSTOM_TOKEN>"
            return data

        if isinstance(data, dict):
            sanitized_dict = {}
            for k, v in data.items():
                k_str = str(k)
                if any(term in k_str.lower() for term in cls.SECRET_KEY_TERMS):
                    sanitized_dict[k_str] = "<REDACTED_SECRET_FIELD>"
                else:
                    sanitized_dict[k_str] = cls.sanitize(v, custom_tokens)
            return sanitized_dict

        if isinstance(data, list):
            return [cls.sanitize(item, custom_tokens) for item in data]

        return data
