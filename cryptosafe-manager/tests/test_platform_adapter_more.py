import types

import src.core.clipboard.platform_adapter as pa


def test_windows_adapter_copy_clear_get():
    class FakeWin32:
        CF_UNICODETEXT = 13

        def __init__(self):
            self.data = ""

        def OpenClipboard(self):
            pass

        def EmptyClipboard(self):
            self.data = ""

        def SetClipboardText(self, data, _fmt):
            self.data = data

        def GetClipboardData(self, _fmt):
            return self.data

        def CloseClipboard(self):
            pass

    old_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "win32clipboard":
            return FakeWin32()
        return old_import(name, *args, **kwargs)

    import builtins
    original_import = builtins.__import__
    builtins.__import__ = fake_import
    try:
        adapter = pa.WindowsClipboardAdapter()
        assert adapter.copy_to_clipboard("hello") is True
        assert adapter.get_clipboard_content() == "hello"
        assert adapter.clear_clipboard() is True
        assert adapter.get_clipboard_content() == ""
    finally:
        builtins.__import__ = original_import


def test_windows_adapter_failure_on_copy():
    class FakeWin32Bad:
        CF_UNICODETEXT = 13

        def OpenClipboard(self):
            raise RuntimeError("fail")

        def CloseClipboard(self):
            pass

    import builtins
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "win32clipboard":
            return FakeWin32Bad()
        return original_import(name, *args, **kwargs)

    builtins.__import__ = fake_import
    try:
        adapter = pa.WindowsClipboardAdapter()
        assert adapter.copy_to_clipboard("hello") is False
        assert adapter.clear_clipboard() is False
        assert adapter.get_clipboard_content() is None
    finally:
        builtins.__import__ = original_import


def test_macos_adapter_with_appkit_path():
    class FakePasteboard:
        def __init__(self):
            self.value = ""

        def clearContents(self):
            self.value = ""

        def declareTypes_owner_(self, *_args):
            return None

        def setString_forType_(self, data, _type):
            self.value = data
            return True

        def stringForType_(self, _type):
            return self.value

    pb = FakePasteboard()

    class FakeNSPasteboard:
        @staticmethod
        def generalPasteboard():
            return pb

    adapter = pa.MacOSClipboardAdapter()
    adapter._appkit = (FakeNSPasteboard, "public.utf8-plain-text")

    assert adapter.copy_to_clipboard("hello") is True
    assert adapter.get_clipboard_content() == "hello"
    assert adapter.clear_clipboard() is True
    assert adapter.get_clipboard_content() == ""


def test_macos_adapter_subprocess_failure(monkeypatch):
    def bad_run(*_args, **_kwargs):
        raise RuntimeError("fail")

    monkeypatch.setattr(pa, "subprocess", types.SimpleNamespace(run=bad_run))

    adapter = pa.MacOSClipboardAdapter()
    adapter._appkit = None

    assert adapter.copy_to_clipboard("hello") is False
    assert adapter.get_clipboard_content() is None


def test_linux_adapter_delegates_to_fallback(monkeypatch):
    calls = []

    class DummyFallback:
        def copy_to_clipboard(self, data):
            calls.append(("copy", data))
            return True

        def clear_clipboard(self):
            calls.append(("clear", None))
            return True

        def get_clipboard_content(self):
            calls.append(("get", None))
            return "linux-data"

    monkeypatch.setattr(pa, "PyperclipClipboardAdapter", lambda: DummyFallback())

    adapter = pa.LinuxClipboardAdapter()
    assert adapter.copy_to_clipboard("x") is True
    assert adapter.clear_clipboard() is True
    assert adapter.get_clipboard_content() == "linux-data"
    assert calls[0] == ("copy", "x")