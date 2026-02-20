# CryptoSafe Manager (Sprint 1)

CryptoSafe Manager — настольный менеджер секретов/паролей с **зашифрованной** базой данных, модульной архитектурой и расширяемым GUI.  

> ⚠️ **Важно:** в Спринте 1 используется **криптографическая заглушка (XOR)** вместо настоящего AES-GCM. Это сделано намеренно для построения архитектуры. Реальная криптография появится в **Спринте 3**.

---

## Видение проекта

Цель проекта — безопасное локальное хранилище учётных данных и секретов:

- Надёжное хранение записей (логины, пароли, заметки, ссылки, теги)
- Реальная криптография: AES-GCM + KDF + управление ключами
- Журнал аудита (подписанные события)
- Безопасный буфер обмена (таймер очистки)
- Авто-блокировка при неактивности
- Backup/restore, импорт/экспорт, упаковка приложения

---

## Roadmap: 8 спринтов

1. **Sprint 1 (текущий):** фундамент (архитектура, схема БД, заглушки crypto/key, EventBus, GUI shell, тесты, CI)
2. **Sprint 2:** KeyStore + хранение мастер-пароля (salt+hash+params), unlock flow (блок/разблок)
3. **Sprint 3:** замена XOR на **AES-GCM**, версии записей/миграции, ротация ключей
4. **Sprint 4:** безопасный буфер обмена (ClipboardCopied/Cleared), таймер очистки
5. **Sprint 5:** полноценный аудит-лог + подписи, просмотр в GUI
6. **Sprint 6:** теги/поиск/фильтрация, улучшение UX
7. **Sprint 7:** авто-блокировка по неактивности, сессионные политики
8. **Sprint 8:** backup/restore, импорт/экспорт, сборка/дистрибуция (Docker/инсталляторы)

---

## Архитектура и структура (MVC-подобная)

Код разделён на модули по принципу MVC/слоёв:

- **Model**: `src/database/` — SQLite schema, helper, модели (Sprint 1)
- **Core / Controller**: `src/core/` — бизнес-логика, crypto/key, события, состояние, конфиги
- **View**: `src/gui/` — Tkinter GUI и переиспользуемые виджеты

### Поток (MVC)
1) GUI инициирует действие (например: добавить запись)  
2) Core шифрует данные и пишет в DB  
3) Core публикует событие в EventBus (`EntryAdded`)  
4) AuditLogger (подписчик) пишет строку в `audit_log`  
5) GUI обновляет таблицу

---

## Структура репозитория

```text
cryptosafe-manager/
├── src/
│   ├── core/
│   │   ├── crypto/
│   │   │   ├── abstract.py       # EncryptionService
│   │   │   └── placeholder.py    # XOR заглушка (Sprint 1)
│   │   ├── audit.py              # подписчик событий -> audit_log
│   │   ├── config.py             # ConfigManager (dev/prod)
│   │   ├── events.py             # EventBus (sync + async)
│   │   ├── key_manager.py        # derive_key + заглушки store/load
│   │   ├── state_manager.py      # состояние (lock/clipboard/idle)
│   │   └── utils.py              # валидация + secure zeroization
│   ├── database/
│   │   ├── models.py             # dataclasses моделей
│   │   └── db.py                 # SQLite helper + user_version + pool
│   └── gui/
│       ├── main_window.py        # главное окно + мастер настройки
│       └── widgets/
│           ├── password_entry.py # masked entry + show/hide
│           ├── secure_table.py   # таблица записей
│           ├── settings_dialog.py# заглушка настроек
│           └── audit_log_viewer.py # заглушка аудита
├── tests/
├── requirements.txt
├── Dockerfile                    # заглушка (Sprint 8)
└── .github/workflows/tests.yml   # CI тестов
