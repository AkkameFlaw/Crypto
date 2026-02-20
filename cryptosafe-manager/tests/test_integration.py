import os
import tempfile

import pytest

from src.core.config import ConfigManager
from src.database.db import Database


def test_config_load_save_roundtrip(tmp_path):
    os.environ["XDG_CONFIG_HOME"] = str(tmp_path)
    mgr = ConfigManager(env="development")
    cfg = mgr.load()
    cfg.language = "ru"
    mgr.save(cfg)
    cfg2 = mgr.load()
    assert cfg2.language == "ru"


@pytest.mark.skipif(os.environ.get("CI") == "true", reason="Tkinter GUI may be unavailable in CI environment")
def test_main_window_instantiation_smoke():
    from src.gui.main_window import MainWindow

    app = MainWindow()
    app.update_idletasks()
    app.destroy()
