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
    database = Database(temp_db_path, pool_size=2)
    database.initialize()
    yield database
    database.close()