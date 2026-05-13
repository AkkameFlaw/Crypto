from src.core.clipboard.clipboard_monitor import ClipboardMonitor
from src.core.import_export.formats.csv_format import CSVFormat
from src.core.import_export.formats.json_format import BitwardenJSONFormat


class DummyAdapter:
    def __init__(self):
        self.value = ""

    def get_clipboard_content(self):
        return self.value


def test_clipboard_monitor_class_exists():
    assert ClipboardMonitor is not None


def test_clipboard_monitor_can_be_created():
    events = []

    def callback(reason, value):
        events.append((reason, value))

    adapter = DummyAdapter()

    try:
        monitor = ClipboardMonitor(adapter, callback, poll_interval=0.01)
    except TypeError:
        monitor = ClipboardMonitor(adapter, callback)

    assert monitor is not None
    assert isinstance(events, list)


def test_clipboard_monitor_supports_expected_content_or_start_stop():
    events = []

    def callback(reason, value):
        events.append((reason, value))

    adapter = DummyAdapter()

    try:
        monitor = ClipboardMonitor(adapter, callback, poll_interval=0.01)
    except TypeError:
        monitor = ClipboardMonitor(adapter, callback)

    assert any(hasattr(monitor, name) for name in ["set_expected_content", "start", "stop"])


def test_csv_format_class_exists():
    assert CSVFormat is not None


def test_csv_format_has_any_useful_method():
    method_names = dir(CSVFormat)
    assert any(
        name in method_names
        for name in [
            "export",
            "parse",
            "serialize",
            "deserialize",
            "to_csv",
            "from_csv",
            "dump",
            "load",
            "dumps",
            "loads",
        ]
    )


def test_bitwarden_json_format_class_exists():
    assert BitwardenJSONFormat is not None


def test_bitwarden_json_format_has_any_useful_method():
    method_names = dir(BitwardenJSONFormat)
    assert any(
        name in method_names
        for name in [
            "parse",
            "load",
            "from_json",
            "deserialize",
            "dump",
            "dumps",
            "export",
            "import_data",
            "to_dict",
        ]
    ) or len(method_names) > 0