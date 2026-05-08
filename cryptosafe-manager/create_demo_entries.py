from __future__ import annotations

from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus
from src.core.vault import AESGCMEntryEncryptionService, EntryManager
from src.database.db import Database


DB_PATH = r"C:\Users\User\AppData\Roaming\cryptosafe-manager\vault.sqlite3"
MASTER_PASSWORD = "SuperAngel3333!"


def main() -> None:
    db = Database(DB_PATH)
    db.initialize()

    bus = EventBus()
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), bus)

    ok, msg = auth.authenticate(MASTER_PASSWORD)
    if not ok:
        print("ERROR: не удалось открыть vault")
        print("Причина:", msg)
        return

    manager = EntryManager(db, AESGCMEntryEncryptionService(auth), bus)

    entries = [
        {
            "title": "GitHub Personal",
            "username": "user.github@example.com",
            "password": "GhDemoPass!2026",
            "url": "https://github.com",
            "notes": "Личный GitHub аккаунт",
            "category": "Development",
            "tags": "git,code,personal",
        },
        {
            "title": "Gmail Main",
            "username": "user.mail@example.com",
            "password": "MailStrong!2026",
            "url": "https://mail.google.com",
            "notes": "Основная электронная почта",
            "category": "Email",
            "tags": "mail,google",
        },
        {
            "title": "Telegram",
            "username": "+79990001122",
            "password": "TelegramSafe!77",
            "url": "https://web.telegram.org",
            "notes": "Телеграм аккаунт",
            "category": "Messenger",
            "tags": "chat,mobile",
        },
        {
            "title": "AWS Console",
            "username": "cloud.admin@example.com",
            "password": "AwsRootSafe!2026",
            "url": "https://aws.amazon.com/console/",
            "notes": "Тестовая запись для облачной инфраструктуры",
            "category": "Cloud",
            "tags": "aws,cloud,infra",
        },
        {
            "title": "Notion Workspace",
            "username": "workspace.user@example.com",
            "password": "NotionPass!2026",
            "url": "https://www.notion.so",
            "notes": "Рабочее пространство Notion",
            "category": "Productivity",
            "tags": "docs,notes,workspace",
        },
        {
            "title": "Figma Team",
            "username": "design.user@example.com",
            "password": "FigmaStrong!2026",
            "url": "https://www.figma.com",
            "notes": "Дизайн-команда",
            "category": "Design",
            "tags": "design,ui,team",
        },
        {
            "title": "University Portal",
            "username": "student_2026",
            "password": "StudyPortal!2026",
            "url": "https://portal.example.edu",
            "notes": "Университетский кабинет",
            "category": "Education",
            "tags": "study,portal",
        },
        {
            "title": "Steam",
            "username": "gamer_user",
            "password": "SteamPlay!2026",
            "url": "https://store.steampowered.com",
            "notes": "Игровая библиотека",
            "category": "Gaming",
            "tags": "games,steam",
        },
        {
            "title": "Dropbox",
            "username": "files.user@example.com",
            "password": "DropboxSafe!2026",
            "url": "https://www.dropbox.com",
            "notes": "Облачное хранилище файлов",
            "category": "Storage",
            "tags": "files,backup,cloud",
        },
        {
            "title": "LinkedIn",
            "username": "career.user@example.com",
            "password": "LinkedCareer!2026",
            "url": "https://www.linkedin.com",
            "notes": "Профессиональный профиль",
            "category": "Career",
            "tags": "career,network",
        },
        {
            "title": "YouTube",
            "username": "video.user@example.com",
            "password": "YoutubeSafe!2026",
            "url": "https://www.youtube.com",
            "notes": "Основной аккаунт YouTube",
            "category": "Media",
            "tags": "video,google,media",
        },
        {
            "title": "Netflix",
            "username": "stream.user@example.com",
            "password": "NetflixStrong!2026",
            "url": "https://www.netflix.com",
            "notes": "Стриминговый сервис",
            "category": "Entertainment",
            "tags": "movies,streaming",
        },
        {
            "title": "Spotify",
            "username": "music.user@example.com",
            "password": "SpotifyPlay!2026",
            "url": "https://open.spotify.com",
            "notes": "Музыкальный сервис",
            "category": "Music",
            "tags": "music,audio",
        },
        {
            "title": "Discord",
            "username": "discord_user",
            "password": "DiscordTalk!2026",
            "url": "https://discord.com",
            "notes": "Игровой и рабочий чат",
            "category": "Communication",
            "tags": "chat,community",
        },
        {
            "title": "Trello",
            "username": "pm.user@example.com",
            "password": "TrelloBoard!2026",
            "url": "https://trello.com",
            "notes": "Планирование задач",
            "category": "Productivity",
            "tags": "tasks,planning",
        },
        {
            "title": "Jira",
            "username": "jira.user@example.com",
            "password": "JiraSprint!2026",
            "url": "https://www.atlassian.com/software/jira",
            "notes": "Трекер задач команды",
            "category": "Work",
            "tags": "jira,agile,team",
        },
        {
            "title": "Confluence",
            "username": "wiki.user@example.com",
            "password": "ConfluenceDoc!2026",
            "url": "https://www.atlassian.com/software/confluence",
            "notes": "Корпоративная документация",
            "category": "Documentation",
            "tags": "wiki,docs",
        },
        {
            "title": "PayPal",
            "username": "pay.user@example.com",
            "password": "PaySafe!2026",
            "url": "https://www.paypal.com",
            "notes": "Платёжный аккаунт",
            "category": "Finance",
            "tags": "money,payments",
        },
        {
            "title": "Revolut",
            "username": "bank.user@example.com",
            "password": "RevolutCard!2026",
            "url": "https://www.revolut.com",
            "notes": "Мобильный банк",
            "category": "Banking",
            "tags": "bank,finance,card",
        },
        {
            "title": "Adobe Creative Cloud",
            "username": "creative.user@example.com",
            "password": "AdobeCreative!2026",
            "url": "https://creativecloud.adobe.com",
            "notes": "Adobe аккаунт для дизайна и видео",
            "category": "Creative",
            "tags": "adobe,design,video",
        },
    ]

    created = 0
    for entry in entries:
        try:
            row = manager.create_entry(entry)
            print(f"CREATED: id={row.id} title={entry['title']}")
            created += 1
        except Exception as e:
            print(f"FAILED: {entry['title']} -> {e}")

    print(f"\nГотово. Создано записей: {created}")

    auth.logout()
    db.close()


if __name__ == "__main__":
    main()