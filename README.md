# CryptoSafe Manager

CryptoSafe Manager — это локальный настольный менеджер паролей, разработанный на Python.  
Приложение предназначено для безопасного хранения учётных данных, локального шифрования записей, контролируемого копирования секретов через защищённый буфер обмена, ведения аудита действий пользователя, импорта и экспорта данных, а также поддержки дополнительных защитных механизмов: auto-lock, panic mode, system tray integration и security profiles.

Проект выполнен как учебный, но построен по принципам реального secure desktop application:
- секреты хранятся локально;
- доступ защищён мастер-паролем;
- записи шифруются;
- критические действия логируются;
- поддерживаются сценарии резервного копирования и миграции данных.

---

# 1. Возможности приложения

## 1.1 Vault / Password Manager
- создание локального хранилища;
- вход по мастер-паролю;
- добавление записей;
- редактирование записей;
- удаление записей;
- поиск по vault;
- генератор паролей.

## 1.2 Безопасность
- локальное шифрование записей;
- secure clipboard с автоочисткой;
- auto-lock при неактивности;
- security profiles;
- panic mode;
- secure memory helpers;
- side-channel related helper logic.

## 1.3 Аудит
- журнал событий;
- фиксация security-чувствительных действий;
- поддержка verifier/signer-related audit flow.

## 1.4 Import / Export / Sharing
- export в native encrypted JSON;
- export в CSV;
- export в Bitwarden JSON;
- export в LastPass CSV;
- import из native JSON;
- import из CSV;
- import из Bitwarden JSON;
- import из LastPass CSV;
- sharing backend;
- QR/key exchange backend.

## 1.5 Usability
- GUI на Tkinter;
- tray integration;
- quick actions через трей;
- status updates;
- search field;
- copy username/password actions.

---

# 2. Технологии

Проект использует следующие технологии:

- **Python** — основной язык разработки;
- **Tkinter** — графический интерфейс;
- **SQLite** — локальное хранение данных;
- **AES-GCM** — шифрование записей;
- **PBKDF2 / Argon2-related components** — derivation ключей;
- **pyperclip** — работа с буфером обмена;
- **pystray** — работа с системным треем;
- **pytest** — модульное тестирование;
- **pytest-cov** — покрытие тестами;
- **PyInstaller** — сборка исполняемого приложения.

---

# 3. Структура проекта

```text
cryptosafe-manager/
│
├── src/
│   ├── core/
│   │   ├── audit/
│   │   ├── clipboard/
│   │   ├── crypto/
│   │   ├── import_export/
│   │   ├── security/
│   │   ├── vault/
│   │   ├── config.py
│   │   ├── events.py
│   │   ├── key_manager.py
│   │   ├── state_manager.py
│   │   └── utils.py
│   │
│   ├── database/
│   │   ├── db.py
│   │   └── models.py
│   │
│   └── gui/
│       ├── main_window.py
│       └── widgets/
│
├── tests/
│   ├── report/
│   └── test_*.py
│
├── docs/
│   ├── user_guide.md
│   └── technical.md
│
├── run.py
├── requirements.txt
├── pytest.ini
├── build_exe.bat
└── README.md
```

---

# 4. Архитектура

Общая архитектура приложения:

```text
GUI (Tkinter)
    ↓
Core services
    ↓
Database (SQLite)
```

## 4.1 GUI layer
`src/gui/`
- отвечает за окна, диалоги, таблицы, кнопки и действия пользователя;
- вызывает core-логику;
- не содержит основную криптографическую бизнес-логику.

## 4.2 Core layer
`src/core/`
- реализует основную функциональность приложения:
  - аутентификацию,
  - derivation ключей,
  - шифрование записей,
  - clipboard control,
  - audit logging,
  - import/export,
  - panic mode,
  - tray behavior,
  - activity monitoring.

## 4.3 Database layer
`src/database/`
- содержит работу с SQLite;
- выполняет CRUD-операции;
- хранит vault entries, audit log, settings, contacts, deleted entries и др.

---

# 5. Криптографическая модель

## 5.1 Master password
Пользователь открывает vault с помощью мастер-пароля.

## 5.2 Derivation ключа
Мастер-пароль не должен использоваться напрямую как ключ.  
Для derivation используются PBKDF2 / Argon2-related mechanisms.

## 5.3 Шифрование записей
Для защиты записей используется `AES-GCM` через `AESGCMEntryEncryptionService`.

Преимущества:
- конфиденциальность;
- контроль целостности;
- стандартный и современный AEAD-подход.

## 5.4 Legacy compatibility
В проекте также присутствует legacy-compatible путь для старых данных через placeholder logic.

---

# 6. Установка и запуск из исходников

## 6.1 Требования
Рекомендуется:
- Python 3.12 или 3.13  
  (у вас проект также запускался на Python 3.14, но для packaging иногда стабильнее 3.12/3.13)
- Windows PowerShell / cmd

## 6.2 Клонирование проекта

```bash
git clone <repo_url>
cd cryptosafe-manager
```

## 6.3 Создание виртуального окружения

### PowerShell
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### cmd
```bat
python -m venv .venv
.venv\Scripts\activate.bat
```

## 6.4 Установка зависимостей

```bash
pip install -r requirements.txt
```

## 6.5 Запуск приложения

```bash
python run.py
```

Если требуется явный `PYTHONPATH`:

```powershell
$env:PYTHONPATH="."
python run.py
```

---

# 7. Первый запуск

При первом запуске приложение предложит:
- выбрать путь к файлу базы данных;
- создать мастер-пароль.

После этого vault будет инициализирован.

## Важно
- мастер-пароль нужно запомнить;
- потеря мастер-пароля может означать потерю доступа к данным;
- рекомендуется использовать длинный и уникальный пароль.

---

# 8. Работа с приложением

## 8.1 Вход
Если хранилище уже существует:
1. запустите приложение;
2. введите мастер-пароль;
3. нажмите вход.

## 8.2 Добавление записи
1. Нажмите **Добавить**.
2. Заполните поля:
   - Title
   - Username
   - Password
   - URL
   - Notes
   - Category
   - Tags
3. Нажмите **Сохранить**.

## 8.3 Редактирование записи
1. Выберите запись в таблице.
2. Нажмите **Изменить**.
3. Измените поля.
4. Сохраните изменения.

## 8.4 Удаление записи
1. Выберите запись.
2. Нажмите **Удалить**.
3. Подтвердите действие.

## 8.5 Поиск
Поиск работает по:
- title,
- username,
- url,
- notes,
- category,
- tags.

Поддерживается и полевая форма поиска, например:
- `category:work`
- `tags:mail`

---

# 9. Secure Clipboard

Приложение поддерживает защищённую работу с буфером обмена.

## Что можно делать
- копировать пароль;
- копировать логин;
- очищать буфер вручную;
- использовать автоочистку.

## Как это работает
После копирования секрет помещается в буфер обмена на ограниченное время.  
Затем он автоматически очищается.

Это снижает риск случайной утечки секрета через clipboard.

---

# 10. Import / Export

## 10.1 Поддерживаемые форматы

### Export
- native encrypted JSON
- CSV
- Bitwarden JSON
- LastPass CSV

### Import
- native encrypted JSON
- CSV
- Bitwarden JSON
- LastPass CSV

## 10.2 Export
Чтобы экспортировать данные:
1. нажмите **Экспорт**;
2. выберите формат;
3. задайте параметры;
4. сохраните файл.

## 10.3 Import
Чтобы импортировать данные:
1. нажмите **Импорт**;
2. выберите файл;
3. укажите режим импорта;
4. подтвердите операцию.

---

# 11. Sharing, QR и Key Exchange

Проект содержит backend-логику для:
- обмена отдельными записями;
- share packages;
- key exchange;
- QR-based flows.

Это может использоваться как:
- демонстрация расширения функциональности;
- backend-основа для будущего обмена секретами.

---

# 12. Audit Log

Приложение ведёт журнал событий.

Фиксируются, например:
- вход в vault;
- изменение записей;
- импорт и экспорт;
- удаление данных;
- panic mode;
- security events.

Это повышает прозрачность и проверяемость работы системы.

---

# 13. Security Profiles

Поддерживаются профили безопасности:
- **Standard**
- **Enhanced**
- **Paranoid**

Они влияют на:
- auto-lock;
- clipboard behavior;
- panic mode;
- общую строгость security-поведения.

---

# 14. Auto-lock

Vault может автоматически блокироваться:
- по таймауту бездействия;
- в рамках security flow;
- при panic-related сценариях.

После блокировки требуется повторный ввод мастер-пароля.

---

# 15. Tray Integration

Через системный трей доступны:
- show main window;
- lock / unlock vault;
- quick search;
- clear clipboard;
- panic mode;
- settings;
- exit.

---

# 16. Panic Mode

Panic mode предназначен для экстренного быстрого сокрытия чувствительной информации.

При активации может происходить:
- очистка clipboard;
- блокировка vault;
- очистка runtime secrets;
- скрытие окна;
- завершение приложения.

---

# 17. Тестирование

Проект тестируется через `pytest`.

## Запуск тестов

```powershell
$env:PYTHONPATH="."
python -m pytest
```

## Что покрывается тестами
- key management
- crypto helpers
- vault operations
- clipboard
- import/export formats
- panic mode
- tray/backend logic
- memory helpers
- utils
- DB operations

## Итоговые результаты
На текущем этапе:
- **144 passed**
- **2 skipped**
- **coverage = 80%**
- **время выполнения ≈ 25.66s**

## Где находится HTML-отчёт
```text
tests/report/html/index.html
```

