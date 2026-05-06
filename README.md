# CryptoSafe Manager

CryptoSafe Manager — настольный менеджер секретов и паролей с локальным зашифрованным хранилищем, модульной архитектурой и расширяемым GUI.

На текущем этапе проект включает:

- Sprint 1 — архитектурный фундамент
- Sprint 2 — мастер-пароль, KDF и аутентификация
- Sprint 3 — AES-GCM и CRUD для vault
- Sprint 4 — безопасный буфер обмена
- Sprint 5 — tamper-evident audit log
- Sprint 6 — import/export, sharing, key exchange и QR workflow
- Sprint 7 — security hardening, auto-lock, panic mode и security profiles

---

## Назначение проекта

CryptoSafe Manager предназначен для безопасного хранения и управления конфиденциальными данными:

- логины и пароли
- URL и заметки
- категории и теги
- безопасный обмен отдельными записями
- аудит событий безопасности
- импорт и экспорт данных
- emergency response механизмы

---

## Roadmap по спринтам

### Sprint 1
Базовая архитектура проекта:
- layered / MVC-like structure
- SQLite schema
- EventBus
- GUI shell
- placeholder crypto
- базовые тесты

### Sprint 2
Аутентификация и ключи:
- мастер-пароль
- Argon2 / PBKDF2
- key cache
- login / logout flow
- password rotation

### Sprint 3
Vault и CRUD:
- AES-256-GCM для записей
- create / read / update / delete
- password generator
- search / filter
- vault table UI

### Sprint 4
Безопасный clipboard:
- copy username/password
- auto-clear
- clipboard monitor
- clipboard status

### Sprint 5
Audit logging:
- tamper-evident audit log
- signatures / hash chain
- integrity verification
- audit viewer
- export of audit data

### Sprint 6
Import / Export / Sharing:
- encrypted export/import
- CSV / Bitwarden / LastPass compatibility
- sharing entry packages
- key exchange
- QR generation workflow
- contacts and history tables

### Sprint 7
Security hardening:
- side-channel protection helpers
- secure memory handling
- activity monitor and auto-lock
- panic mode
- security profiles
- GUI integration for re-lock / security state

### Sprint 8
Планируется:
- backup / restore
- packaging / distribution
- release artifacts / installer

---

## Архитектура

Проект организован по слоям:

- `src/core/` — бизнес-логика, криптография, clipboard, audit, import/export, security
- `src/database/` — SQLite, schema, migrations, data access
- `src/gui/` — GUI и виджеты
- `tests/` — unit tests, integration tests и demo scenarios

### Упрощённый поток работы

1. GUI получает действие пользователя  
2. Core проверяет аутентификацию и состояние vault  
3. Core выполняет шифрование / дешифрование / обработку  
4. Database сохраняет изменения  
5. EventBus публикует событие  
6. Audit logger пишет его в журнал  
7. GUI обновляет интерфейс

---

## Структура репозитория

```text
cryptosafe-manager/
├── src/
│   ├── core/
│   │   ├── audit/
│   │   ├── clipboard/
│   │   ├── crypto/
│   │   ├── import_export/
│   │   │   ├── formats/
│   │   │   ├── exporter.py
│   │   │   ├── importer.py
│   │   │   ├── sharing_service.py
│   │   │   └── key_exchange.py
│   │   ├── security/
│   │   │   ├── side_channel_protection.py
│   │   │   ├── memory_guard.py
│   │   │   ├── activity_monitor.py
│   │   │   └── panic_mode.py
│   │   ├── vault/
│   │   ├── events.py
│   │   ├── config.py
│   │   └── state_manager.py
│   ├── database/
│   │   ├── db.py
│   │   └── models.py
│   └── gui/
│       ├── main_window.py
│       └── widgets/
│           ├── password_entry.py
│           ├── secure_table.py
│           ├── settings_dialog.py
│           ├── audit_log_viewer.py
│           └── import_export_dialogs.py
├── tests/
├── requirements.txt
├── README.md
└── .github/workflows/tests.yml
