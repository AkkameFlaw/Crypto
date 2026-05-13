import src.database.models as models


def test_models_module_has_vault_entry():
    assert hasattr(models, "VaultEntry")


def test_vault_entry_can_be_created():
    VaultEntry = getattr(models, "VaultEntry")

    fields = getattr(VaultEntry, "__annotations__", {})
    kwargs = {}

    if "id" in fields:
        kwargs["id"] = 1
    if "title" in fields:
        kwargs["title"] = "GitHub"
    if "username" in fields:
        kwargs["username"] = "user"
    if "encrypted_password" in fields:
        kwargs["encrypted_password"] = b"abc"
    if "url" in fields:
        kwargs["url"] = "https://github.com"
    if "notes" in fields:
        kwargs["notes"] = "note"
    if "tags" in fields:
        kwargs["tags"] = "git,code"
    if "created_at" in fields:
        kwargs["created_at"] = 100
    if "updated_at" in fields:
        kwargs["updated_at"] = 200

    entry = VaultEntry(**kwargs)

    for key, value in kwargs.items():
        assert getattr(entry, key) == value


def test_models_module_exports_something():
    exported = [name for name in dir(models) if not name.startswith("_")]
    assert len(exported) > 0