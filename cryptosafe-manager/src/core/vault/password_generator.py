from __future__ import annotations

import secrets
from collections import deque
from dataclasses import dataclass
from typing import Deque, Iterable


@dataclass
class PasswordGeneratorOptions:
    length: int = 16
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_special: bool = True
    exclude_ambiguous: bool = True


class PasswordGenerator:
    UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    LOWER = "abcdefghijklmnopqrstuvwxyz"
    DIGITS = "0123456789"
    SPECIAL = "!@#$%^&*"
    AMBIGUOUS = set("lI10O")

    def __init__(self, history_size: int = 20) -> None:
        self._history: Deque[str] = deque(maxlen=history_size)

    def generate(self, options: PasswordGeneratorOptions | None = None) -> str:
        options = options or PasswordGeneratorOptions()
        self._validate_options(options)

        pools = []
        if options.use_upper:
            pools.append(self._filtered(self.UPPER, options.exclude_ambiguous))
        if options.use_lower:
            pools.append(self._filtered(self.LOWER, options.exclude_ambiguous))
        if options.use_digits:
            pools.append(self._filtered(self.DIGITS, options.exclude_ambiguous))
        if options.use_special:
            pools.append(self.SPECIAL)

        if not pools:
            raise ValueError("At least one character set must be enabled")

        flat = "".join(pools)

        for _ in range(100):
            chars = [secrets.choice(pool) for pool in pools]
            while len(chars) < options.length:
                chars.append(secrets.choice(flat))
            self._shuffle(chars)
            candidate = "".join(chars)

            if candidate in self._history:
                continue
            if self.score(candidate) < 3:
                continue

            self._history.append(candidate)
            return candidate

        raise RuntimeError("Failed to generate a sufficiently strong unique password")

    def score(self, password: str) -> int:
        score = 0
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in self.SPECIAL for c in password)
        diversity = sum([has_upper, has_lower, has_digit, has_special])
        if diversity >= 3:
            score += 1
        if diversity == 4:
            score += 1
        return min(score, 4)

    @staticmethod
    def _shuffle(chars: list[str]) -> None:
        for i in range(len(chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            chars[i], chars[j] = chars[j], chars[i]

    @classmethod
    def _filtered(cls, s: str, exclude_ambiguous: bool) -> str:
        if not exclude_ambiguous:
            return s
        return "".join(ch for ch in s if ch not in cls.AMBIGUOUS)

    @staticmethod
    def _validate_options(options: PasswordGeneratorOptions) -> None:
        if options.length < 8 or options.length > 64:
            raise ValueError("Password length must be between 8 and 64")