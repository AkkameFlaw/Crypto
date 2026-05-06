from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus
from src.core.import_export import KeyExchangeService, SharingService
from src.core.vault import AESGCMEntryEncryptionService, EntryManager


def test_share_entry_tamper_detection(db):
    bus = EventBus()
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), bus)
    auth.initialize_master_password("StrongPass!123")
    ok, _ = auth.authenticate("StrongPass!123")
    assert ok

    vault = EntryManager(db, AESGCMEntryEncryptionService(auth), bus)
    created = vault.create_entry(
        {
            "title": "Shared Entry",
            "username": "alice",
            "password": "StrongPass!999",
            "url": "https://example.com",
            "notes": "share me",
            "category": "Demo",
            "tags": "shared",
        }
    )

    sharing = SharingService(db, vault)
    result = sharing.share_entry(
        int(created.id),
        options=__import__("types").SimpleNamespace(
            recipient="bob@example.com",
            permissions={"read_only": True, "include_notes": True},
            expires_in_days=7,
            method="password",
            password="SharePass!123",
            public_key_pem=None,
        ),
    )

    package = result["package"]
    tampered = dict(package)
    tampered["data"] = package["data"][:-4] + "AAAA"

    failed = False
    try:
        sharing.import_shared_entry(tampered, password="SharePass!123", save_to_vault=False)
    except Exception:
        failed = True

    assert failed is True