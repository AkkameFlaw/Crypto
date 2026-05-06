from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import zlib
from pathlib import Path

from src.core.import_export import QRCodeService


def main():
    print("\n=== SPRINT 6 / TEST 4 / QR DEMO ===")

    service = QRCodeService()
    payload = b"A" * 1024

    print("1. Payload prepared")
    print("   size =", len(payload), "bytes")

    print("2. Generate QR images...")
    qr_images = service.generate_qr_code(payload)
    print("   qr image count =", len(qr_images))

    print("3. Simulate chunk transport and decode...")
    compressed = zlib.compress(payload)
    chunk_size = 1800
    total = (len(compressed) + chunk_size - 1) // chunk_size

    chunk_strings = []
    for idx in range(total):
        chunk = compressed[idx * chunk_size : (idx + 1) * chunk_size]
        obj = {
            "chunk": idx + 1,
            "total": total,
            "expires_at": "2099-01-01T00:00:00+00:00",
            "checksum": hashlib.sha256(chunk).hexdigest()[:12],
            "data": base64.b64encode(chunk).decode("ascii"),
        }
        chunk_strings.append(json.dumps(obj))

    restored = service.decode_qr_chunks(chunk_strings)
    print("   restored size =", len(restored) if restored else None)

    if restored == payload:
        print("RESULT: OK — QR backend round-trip прошёл")
    else:
        print("RESULT: FAIL — QR backend round-trip не совпал")

if __name__ == "__main__":
    main()