from src.core.vault import PasswordGenerator, PasswordGeneratorOptions


def test_password_generator_bulk():
    gen = PasswordGenerator()
    seen = set()

    for _ in range(1000):
        pwd = gen.generate(PasswordGeneratorOptions(length=16))
        assert len(pwd) == 16
        assert any(c.isupper() for c in pwd)
        assert any(c.islower() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        assert any(c in "!@#$%^&*" for c in pwd)
        assert gen.score(pwd) >= 3
        seen.add(pwd)

    assert len(seen) == 1000