from __future__ import annotations
from dataclasses import dataclass, asdict, field


import json
import os
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional

from .utils import minimal_path_permissions


def _default_config_dir() -> str:
    home = os.path.expanduser("~")
    if os.name == "nt":
        base = os.getenv("APPDATA", home)
    else:
        base = os.getenv("XDG_CONFIG_HOME", os.path.join(home, ".config"))
    return os.path.join(base, "cryptosafe-manager")


@dataclass
class CryptoConfig:
    kdf_iterations: int = 120_000
    kdf_hash: str = "sha256"
    kdf_dklen: int = 32


@dataclass
class AppConfig:
    environment: str = "development"
    db_path: str = ""
    config_dir: str = ""
    crypto: CryptoConfig = field(default_factory=CryptoConfig)

    clipboard_timeout_seconds: int = 0
    auto_lock_seconds: int = 0
    language: str = "ru"
    theme: str = "system"


class ConfigManager:

    def __init__(self, env: str = "development") -> None:
        env = env if env in ("development", "production") else "development"
        self.env = env
        self.config_dir = _default_config_dir()
        self.config_path = os.path.join(self.config_dir, f"config.{env}.json")
        self._config: Optional[AppConfig] = None

    def load(self) -> AppConfig:
        os.makedirs(self.config_dir, exist_ok=True)

        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._config = self._from_dict(data)
                return self._config
            except Exception:
                pass

        cfg = AppConfig(environment=self.env, config_dir=self.config_dir)
        cfg.db_path = os.path.join(self.config_dir, "vault.sqlite3")
        self._config = cfg
        self.save(cfg)
        return cfg

    def save(self, cfg: AppConfig) -> None:
        os.makedirs(self.config_dir, exist_ok=True)
        data = asdict(cfg)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        minimal_path_permissions(self.config_path)

    @staticmethod
    def _from_dict(d: Dict[str, Any]) -> AppConfig:
        crypto = d.get("crypto", {}) or {}
        cfg = AppConfig(
            environment=str(d.get("environment", "development")),
            db_path=str(d.get("db_path", "")),
            config_dir=str(d.get("config_dir", "")),
            crypto=CryptoConfig(
                kdf_iterations=int(crypto.get("kdf_iterations", 120_000)),
                kdf_hash=str(crypto.get("kdf_hash", "sha256")),
                kdf_dklen=int(crypto.get("kdf_dklen", 32)),
            ),
            clipboard_timeout_seconds=int(d.get("clipboard_timeout_seconds", 0)),
            auto_lock_seconds=int(d.get("auto_lock_seconds", 0)),
            language=str(d.get("language", "ru")),
            theme=str(d.get("theme", "system")),
        )

        if not cfg.config_dir:
            cfg.config_dir = _default_config_dir()

        if not cfg.db_path:
            cfg.db_path = os.path.join(cfg.config_dir, "vault.sqlite3")
        return cfg
