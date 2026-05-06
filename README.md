# CryptoSafe Manager

CryptoSafe Manager — настольный менеджер секретов и паролей с локальным зашифрованным хранилищем, модульной архитектурой и расширяемым GUI.

> В проекте используется поэтапная реализация по спринтам. На текущем этапе добавлены:
> - Sprint 1 — архитектурный фундамент
> - Sprint 2 — мастер-пароль, KDF и аутентификация
> - Sprint 3 — AES-GCM и CRUD для хранилища
> - Sprint 4 — безопасный буфер обмена
> - Sprint 5 — tamper-evident audit log
> - Sprint 6 — import/export, sharing, key exchange, QR workflow

---

## Что делает проект

CryptoSafe Manager предназначен для безопасного хранения и управления секретами:

- хранение логинов, паролей, URL, заметок, тегов и категорий
- шифрование записей на уровне vault
- мастер-пароль и управление ключами
- журнал аудита с контролем целостности
- безопасный буфер обмена с автоочисткой
- импорт и экспорт данных
- обмен отдельными записями
- QR-based workflow для передачи share package / ключей

---

## Roadmap по спринтам

### Sprint 1
Базовая архитектура проекта:
- MVC / layered structure
- SQLite schema
- crypto placeholders
- EventBus
- GUI shell
- базовые тесты

### Sprint 2
Аутентификация и управление ключами:
- мастер-пароль
- Argon2 / PBKDF2
- key cache
- login flow
- password rotation

### Sprint 3
Полноценное vault-хранилище:
- AES-256-GCM для записей
- CRUD
- password generator
- search/filter
- табличный интерфейс

### Sprint 4
Безопасный буфер обмена:
- copy password / username
- auto-clear timer
- clipboard monitor
- secure clipboard state

### Sprint 5
Журнал аудита:
- tamper-evident audit log
- подпись / hash chain
- viewer
- экспорт аудита
- integrity verification

### Sprint 6
Импорт, экспорт и обмен:
- encrypted export/import
- CSV / Bitwarden / LastPass compatibility
- selective export
- sharing отдельных записей
- public/private key exchange
- QR generation workflow
- contacts + history tables

### Sprint 7
Планируется:
- auto-lock policies
- panic mode
- session hardening

### Sprint 8
Планируется:
- backup / restore
- packaging / distribution
- installer / Docker / release artifacts

---

## Архитектура

Проект разделён по слоям:

- `src/core/` — бизнес-логика, криптография, import/export, audit, clipboard
- `src/database/` — база данных, миграции, доступ к SQLite
- `src/gui/` — пользовательский интерфейс и виджеты
- `tests/` — unit, integration и demo scenarios

### Упрощённый поток MVC

1. GUI инициирует действие пользователя  
2. Core проверяет сессию и ключи  
3. Core шифрует / обрабатывает данные  
4. Database сохраняет изменения  
5. EventBus публикует событие  
6. Audit logger пишет событие в журнал  
7. GUI обновляет состояние

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
