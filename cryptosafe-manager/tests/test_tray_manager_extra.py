import types

import src.core.clipboard.platform_adapter as pa


def test_pyperclip_adapter_success(monkeypatch):
    monkeypatch.setattr(pa.pyperclip, "copy", lambda data: None)
    monkeypatch.setattr(pa.pyperclip, "paste", lambda: "secret")

    adapter = pa.PyperclipClipboardAdapter()

    assert adapter.copy_to_clipboard("hello") is True
    assert adapter.get_clipboard_content() == "secret"
    assert adapter.clear_clipboard() is True


def test_pyperclip_adapter_failure(monkeypatch):
    def bad_copy(_data):
        raise RuntimeError("fail")

    def bad_paste():
        raise RuntimeError("fail")

    monkeypatch.setattr(pa.pyperclip, "copy", bad_copy)
    monkeypatch.setattr(pa.pyperclip, "paste", bad_paste)

    adapter = pa.PyperclipClipboardAdapter()

    assert adapter.copy_to_clipboard("hello") is False
    assert adapter.clear_clipboard() is False
    assert adapter.get_clipboard_content() is None


def test_linux_clipboard_adapter_uses_fallback(monkeypatch):
    class DummyFallback:
        def copy_to_clipboard(self, data):
            return data == "x"

        def clear_clipboard(self):
            return True

        def get_clipboard_content(self):
            return "ok"

    monkeypatch.setattr(pa, "PyperclipClipboardAdapter", lambda: DummyFallback())

    adapter = pa.LinuxClipboardAdapter()
    assert adapter.copy_to_clipboard("x") is True
    assert adapter.clear_clipboard() is True
    assert adapter.get_clipboard_content() == "ok"


def test_macos_clipboard_adapter_subprocess_fallback(monkeypatch):
    monkeypatch.setattr(pa, "subprocess", types.SimpleNamespace(
        run=lambda *args, **kwargs: types.SimpleNamespace(stdout=b"clip-data")
    ))

    adapter = pa.MacOSClipboardAdapter()
    adapter._appkit = None

    assert adapter.copy_to_clipboard("hello") is True
    assert adapter.clear_clipboard() is True
    assert adapter.get_clipboard_content() == "clip-data"


def test_create_clipboard_adapter_windows(monkeypatch):
    monkeypatch.setattr(pa.platform, "system", lambda: "Windows")

    class DummyWin:
        pass

    monkeypatch.setattr(pa, "WindowsClipboardAdapter", lambda: DummyWin())
    adapter = pa.create_clipboard_adapter()
    assert isinstance(adapter, DummyWin)


def test_create_clipboard_adapter_windows_fallback(monkeypatch):
    monkeypatch.setattr(pa.platform, "system", lambda: "Windows")
    monkeypatch.setattr(pa, "WindowsClipboardAdapter", lambda: (_ for _ in ()).throw(RuntimeError("fail")))

    adapter = pa.create_clipboard_adapter()
    assert isinstance(adapter, pa.PyperclipClipboardAdapter)


def test_create_clipboard_adapter_darwin(monkeypatch):
    monkeypatch.setattr(pa.platform, "system", lambda: "Darwin")
    adapter = pa.create_clipboard_adapter()
    assert isinstance(adapter, pa.MacOSClipboardAdapter)


def test_create_clipboard_adapter_linux(monkeypatch):
    monkeypatch.setattr(pa.platform, "system", lambda: "Linux")
    adapter = pa.create_clipboard_adapter()
    assert isinstance(adapter, pa.LinuxClipboardAdapter)


def test_create_clipboard_adapter_other(monkeypatch):
    monkeypatch.setattr(pa.platform, "system", lambda: "OtherOS")
    adapter = pa.create_clipboard_adapter()
    assert isinstance(adapter, pa.PyperclipClipboardAdapter)