from src.core.import_export import QRCodeService


def test_qr_chunk_roundtrip():
    service = QRCodeService()
    payload = b"A" * 1024
    chunks = service.generate_qr_code(payload)
    assert len(chunks) >= 1

    import base64, json, zlib, hashlib

    compressed = zlib.compress(payload)
    chunk_size = 1800
    chunk_strings = []
    total = (len(compressed) + chunk_size - 1) // chunk_size
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
    assert restored == payload