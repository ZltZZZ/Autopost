import uuid
from datetime import datetime
from sqlalchemy import MetaData, Table, Column, Integer, String, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import registry, relationship, sessionmaker
from settings import settings
from sqlalchemy import text

DATABASE_URL = f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@db:5432/{settings.POSTGRES_DB}"
mapper_registry = registry()
metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("id", String(128), primary_key=True, nullable=False),
    Column("username", String(128), unique=True, nullable=False),
    Column("email", String(128), unique=True, nullable=False)
)

posts = Table(
    "posts",
    metadata,
    Column("id", String(50), primary_key=True, default=lambda: str(uuid.uuid4())),
    Column("user_id", String(100), ForeignKey("users.id")),
    Column("text", Text),
    Column("created_at", DateTime, default=datetime.now),
    Column("post_at", DateTime)
)

post_media = Table(
    "post_media",
    metadata,
    Column("id", String(50), primary_key=True, default=lambda: str(uuid.uuid4())),
    Column("post_id", String(50), ForeignKey("posts.id")),
    Column("file_type", String(20)),  # 'image' или 'video'
    Column("file_path", String(200))
)

post_hashtags = Table(
    "post_hashtags",
    metadata,
    Column("id", String(50), primary_key=True, default=lambda: str(uuid.uuid4())),
    Column("post_id", String(50), ForeignKey("posts.id")),
    Column("hashtag", String(200))
)

sessions = Table(
    "sessions",
    metadata,
    Column("sid", String(100), primary_key=True, nullable=False),
    Column("user_id", String(100), ForeignKey("users.id")),
    Column("started_at", DateTime, default=datetime.now),
    Column("last_access", DateTime, default=datetime.now),
    Column("ip_address", String(50)),
    Column("user_agent", String(200), nullable=True)
)

temp_links = Table(
    "temp_links",
    metadata,
    Column("id", String(100), primary_key=True, default=lambda: str(uuid.uuid4())),
    Column("user_id", String(100), ForeignKey("users.id")),
    Column("token", String(200), unique=True),
    Column("created_at", DateTime, default=datetime.now),
    Column("expires_at", DateTime),
    Column("keycloak_role", String(200))
)

user_tokens = Table(
    "user_tokens",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", String(100), ForeignKey("users.id")),
    Column("service", String(20)),  # 'telegram', 'vk', 'ok'
    Column("token_type", String(20)),  # 'bot', 'chat', 'group', 'user'
    Column("token_value", String(200)),
    Column("last_updated", DateTime, default=datetime.now)
)

class User:
    def __init__(self, id: str, username: str, email: str, is_active: bool = True):
        self.id = id
        self.username = username
        self.email = email
        self.is_active = is_active

class TemporaryLink:
    def __init__(self, user_id: str, token: str, expires_at: datetime, keycloak_role: str):
        self.user_id = user_id
        self.token = token
        self.expires_at = expires_at
        self.keycloak_role = keycloak_role

class Post:
    def __init__(self, user_id: str, text: str, post_at: datetime):
        self.user_id = user_id
        self.text = text
        self.post_at = post_at

class PostMedia:
    def __init__(self, post_id: str, file_type: str, file_path: str):
        self.post_id = post_id
        self.file_type = file_type
        self.file_path = file_path

class PostHashtag:
    def __init__(self, post_id: str, hashtag: str):
        self.post_id = post_id
        self.hashtag = hashtag

class UserToken:
    def __init__(self, user_id: str, service: str, token_type: str, token_value: str, last_updated: datetime):
        self.user_id = user_id
        self.service = service
        self.token_type = token_type
        self.token_value = token_value
        self.last_updated = last_updated

mapper_registry.map_imperatively(User, users, properties={
    'temp_links': relationship(TemporaryLink, backref='user'),
    'posts': relationship(Post, backref='user'),
    'tokens': relationship(UserToken, backref='user')
})
mapper_registry.map_imperatively(TemporaryLink, temp_links)
mapper_registry.map_imperatively(Post, posts, properties={
    'media': relationship(PostMedia, backref='post'),
    'hashtags': relationship(PostHashtag, backref='post')
})
mapper_registry.map_imperatively(PostMedia, post_media)
mapper_registry.map_imperatively(PostHashtag, post_hashtags)
mapper_registry.map_imperatively(UserToken, user_tokens)

async_engine = create_async_engine(DATABASE_URL, echo=True)
async_session = sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)

class DatabaseManager:
    async def connect(self):
        """Проверка подключения к БД"""
        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        print("✅ Connection to PostgreSQL is successful")

    async def create_tables(self):
        """Создание всех таблиц"""
        async with async_engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        print("✅ Tables have been created successfully")

    async def drop_tables(self):
        """Удаление всех таблиц"""
        async with async_engine.begin() as conn:
            await conn.run_sync(metadata.drop_all)
        print("✅ Tables have been deleted successfully")

db_manager = DatabaseManager()