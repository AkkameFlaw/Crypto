# CryptoSafe Manager (Sprint 1–4)

CryptoSafe Manager — настольный менеджер секретов и паролей с локальным зашифрованным хранилищем, модульной архитектурой и расширяемым графическим интерфейсом.

Проект развивается по спринтам. На текущем этапе реализованы:

- **Sprint 1** — архитектурный фундамент
- **Sprint 2** — аутентификация и управление ключами
- **Sprint 3** — CRUD хранилища и шифрование записей через AES-256-GCM
- **Sprint 4** — безопасный буфер обмена с автоочисткой и мониторингом

> Важно:
> - В **Sprint 1** использовалась криптографическая заглушка XOR.
> - В **Sprint 2** были добавлены Argon2id, PBKDF2, кэширование ключей и смена мастер-пароля.
> - Начиная с **Sprint 3**, новые записи шифруются индивидуально через **AES-256-GCM**.
> - В **Sprint 4** добавлен защищённый clipboard-модуль с автоочисткой, уведомлениями и интеграцией с событиями.

---

## Видение проекта

Цель проекта — безопасное локальное хранилище учётных данных и секретов с возможностью дальнейшего расширения:

- надёжное хранение логинов, паролей, заметок и ссылок
- полноценная криптография: AES-GCM + KDF + управление ключами
- журнал аудита и система событий
- безопасный буфер обмена
- авто-блокировка по неактивности
- поиск, фильтрация, теги, категории
- backup/restore, импорт/экспорт
- подготовка к упаковке и релизу

---

## Roadmap: 8 спринтов

1. **Sprint 1** — фундамент:
   - архитектура
   - схема БД
   - EventBus
   - crypto placeholders
   - базовый GUI
   - тесты и CI

2. **Sprint 2** — аутентификация и управление ключами:
   - Argon2id
   - PBKDF2-HMAC-SHA256
   - login flow
   - in-memory key cache
   - смена мастер-пароля
   - ротация ключей
   - обновление `key_store`

3. **Sprint 3** — CRUD и шифрование записей:
   - AES-256-GCM для каждой записи
   - EntryManager
   - безопасный генератор паролей
   - поиск и фильтрация
   - табличный интерфейс
   - диалог создания/редактирования записи
   - мягкое удаление записей

4. **Sprint 4 (текущий)** — secure clipboard:
   - безопасное копирование в буфер обмена
   - автоочистка по таймеру
   - мониторинг внешнего изменения clipboard
   - статус буфера в интерфейсе
   - copy password / username / all
   - toast-уведомления
   - сохранение таймаута в settings

5. **Sprint 5**
   - полноценный аудит-лог
   - подписи записей журнала
   - просмотр журнала в GUI

6. **Sprint 6**
   - теги
   - расширенный поиск
   - экспорт/обмен
   - общие метаданные

7. **Sprint 7**
   - авто-блокировка по неактивности
   - panic mode
   - политики сессии

8. **Sprint 8**
   - backup/restore
   - упаковка
   - релизная подготовка

---

## Что реализовано по спринтам

## Sprint 1
- модульная архитектура проекта
- схема SQLite
- `ConfigManager`
- `StateManager`
- `EventBus`
- `AuditLogger`
- базовый GUI shell
- тесты и CI

### Ограничения Sprint 1
- вместо реального шифрования использовался XOR placeholder
- не было полноценной аутентификации
- не было управления мастер-паролем

---

## Sprint 2
- аутентификация по мастер-паролю
- Argon2id для проверки пароля
- PBKDF2-HMAC-SHA256 для encryption key
- `SecureKeyCache`
- login dialog
- change password dialog
- ротация ключей
- password policy
- обновлённый `key_store`

### Ограничения Sprint 2
- записи всё ещё шифровались старой XOR-заглушкой

---

## Sprint 3
- AES-256-GCM для каждой записи
- `EntryManager` для CRUD-операций
- безопасный генератор паролей
- поиск в реальном времени
- таблица записей
- форма создания и редактирования записи
- мягкое удаление в `deleted_entries`
- совместимость со старыми записями Sprint 1–2

---

## Sprint 4
- добавлен пакет `src/core/clipboard/`
- реализован `ClipboardService`
- реализован `ClipboardMonitor`
- добавлены platform adapters
- автоочистка буфера обмена
- настройка таймаута очистки
- сохранение таймаута в settings
- copy password / username / all
- статус clipboard в status bar
- toast-уведомления
- очистка clipboard при закрытии приложения
- интеграция с `ClipboardCopied` и `ClipboardCleared`

### Что важно в Sprint 4
Буфер обмена — одно из самых уязвимых мест в менеджерах паролей.  
В Sprint 4 добавлена безопасная модель работы с clipboard:

- чувствительные данные копируются только при разблокированном хранилище
- содержимое автоматически очищается
- новое копирование замещает старое
- внешнее изменение clipboard вызывает защитную реакцию
- в памяти приложения данные хранятся в обфусцированном виде

---

## Архитектура проекта

Проект организован по MVC-подобной схеме.

### Слои
- **View** → `src/gui/`
- **Core / Controller** → `src/core/`
- **Database / Model** → `src/database/`

### Поток работы
1. GUI инициирует действие пользователя  
2. Core обрабатывает бизнес-логику  
3. AuthenticationManager управляет доступом к encryption key  
4. EntryManager выполняет CRUD  
5. ClipboardService управляет clipboard-операциями  
6. Database сохраняет данные  
7. EventBus публикует события  
8. AuditLogger пишет аудит

---

## Структура репозитория

```text
cryptosafe-manager/
├── src/
│   ├── core/
│   │   ├── crypto/
│   │   │   ├── abstract.py
│   │   │   ├── placeholder.py
│   │   │   ├── key_derivation.py
│   │   │   ├── key_storage.py
│   │   │   └── authentication.py
│   │   ├── vault/
│   │   │   ├── encryption_service.py
│   │   │   ├── entry_manager.py
│   │   │   └── password_generator.py
│   │   ├── clipboard/
│   │   │   ├── clipboard_service.py
│   │   │   ├── platform_adapter.py
│   │   │   └── clipboard_monitor.py
│   │   ├── audit.py
│   │   ├── config.py
│   │   ├── events.py
│   │   ├── state_manager.py
│   │   └── utils.py
│   ├── database/
│   │   ├── db.py
│   │   └── models.py
│   └── gui/
│       ├── main_window.py
│       └── widgets/
│           ├── password_entry.py
│           ├── secure_table.py
│           ├── settings_dialog.py
│           └── audit_log_viewer.py
├── tests/
├── requirements.txt
├── Dockerfile
└── .github/workflows/tests.yml
