import src.core.clipboard.platform_adapter as pa


def test_platform_adapter_module_imports():
    assert pa is not None


def test_platform_adapter_exports_something():
    exported = [name for name in dir(pa) if not name.startswith("_")]
    assert len(exported) > 0


def test_platform_adapter_has_base_or_factory():
    names = dir(pa)
    assert any(
        name in names
        for name in [
            "ClipboardAdapter",
            "WindowsClipboardAdapter",
            "MacOSClipboardAdapter",
            "LinuxClipboardAdapter",
            "PyperclipClipboardAdapter",
            "create_clipboard_adapter",
            "get_clipboard_adapter",
        ]
    )


def test_platform_adapter_factory_if_present():
    if hasattr(pa, "create_clipboard_adapter"):
        adapter = pa.create_clipboard_adapter()
        assert adapter is not None
    elif hasattr(pa, "get_clipboard_adapter"):
        adapter = pa.get_clipboard_adapter()
        assert adapter is not None
    else:
        assert True


def test_platform_adapter_declares_adapter_classes():
    names = dir(pa)
    adapter_like = [name for name in names if "Adapter" in name]
    assert len(adapter_like) >= 1