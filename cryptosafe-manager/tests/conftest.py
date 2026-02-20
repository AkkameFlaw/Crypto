import os
import tempfile

import pytest

from src.database.db import Database


@pytest.fixture()
def temp_db_path():
    with tempfile.TemporaryDirectory() as d:
        yield os.path.join(d, "test.sqlite3")


@pytest.fixture()
def db(temp_db_path):
    db = Database(temp_db_path, pool_size=2)
    db.initialize()
    return db
