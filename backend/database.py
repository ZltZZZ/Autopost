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
    Column("id", String(100), primary_key=True, default=lambda: str(uuid.uuid4())),
    Column("username", String(128), unique=True, nullable=False),
    Column("email", String(128), unique=True, nullable=False),
    Column("is_active", Boolean, default=True, nullable=False)
)

sessions = Table(
    "sessions",
    metadata,
    Column("id", String(100), primary_key=True, default=lambda: str(uuid.uuid4())),
    Column("user_id", String(100), ForeignKey("users.id")),
    Column("started_at", DateTime, default=datetime.now),
    Column("last_access", DateTime, default=datetime.now),
    Column("ip_address", String(50)),
    Column("user_agent", String(200), nullable=True),
    Column("is_active", Boolean, default=True, nullable=False)
)

temp_links = Table(
    "temp_links",
    metadata,
    Column("id", String(100), primary_key=True, default=lambda: str(uuid.uuid4())),
    Column("user_id", String(100), ForeignKey("users.id")),
    Column("token", String(200), unique=True),
    Column("created_at", DateTime, default=datetime.now),
    Column("expires_at", DateTime)
)

posts = Table(
    "posts",
    metadata,
    Column("id", String(50), primary_key=True, default=lambda: str(uuid.uuid4())),
    Column("user_id", String(100), ForeignKey("users.id")),
    Column("text", Text),
    Column("created_at", DateTime, default=datetime.now)
)

post_media = Table(
    "post_media",
    metadata,
    Column("id", String(50), primary_key=True, default=lambda: str(uuid.uuid4())),
    Column("post_id", String(50), ForeignKey("posts.id")),
    Column("file_type", String(20)),  # 'image' или 'video'
    Column("file_path", String(200))
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
    
    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}')>"

class Session:
    def __init__(self, user_id: str, ip_address: str, user_agent: str = None, is_active: bool = True):
        self.user_id = user_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.is_active = is_active
    
    def __repr__(self):
        return f"<Session(user_id='{self.user_id}', ip='{self.ip_address}')>"

class TemporaryLink:
    def __init__(self, user_id: str, token: str, expires_at: datetime):
        self.user_id = user_id
        self.token = token
        self.expires_at = expires_at
    
    def __repr__(self):
        return f"<TemporaryLink(user_id='{self.user_id}', token='{self.token[:5]}...')>"

class Post:
    def __init__(self, user_id: str, text: str):
        self.user_id = user_id
        self.text = text
    
    def __repr__(self):
        return f"<Post(user_id='{self.user_id}', text='{self.text[:20]}...')>"

class PostMedia:
    def __init__(self, post_id: str, file_type: str, file_path: str):
        self.post_id = post_id
        self.file_type = file_type
        self.file_path = file_path
    
    def __repr__(self):
        return f"<PostMedia(post_id='{self.post_id}', type='{self.file_type}')>"

class UserToken:
    def __init__(self, user_id: str, service: str, token_type: str, token_value: str):
        self.user_id = user_id
        self.service = service
        self.token_type = token_type
        self.token_value = token_value
    
    def __repr__(self):
        return f"<UserToken(user_id='{self.user_id}', service='{self.service}')>"

mapper_registry.map_imperatively(User, users, properties={
    'sessions': relationship(Session, backref='user'),
    'temp_links': relationship(TemporaryLink, backref='user'),
    'posts': relationship(Post, backref='user'),
    'tokens': relationship(UserToken, backref='user')
})
mapper_registry.map_imperatively(Session, sessions)
mapper_registry.map_imperatively(TemporaryLink, temp_links)
mapper_registry.map_imperatively(Post, posts, properties={
    'media': relationship(PostMedia, backref='post')
})
mapper_registry.map_imperatively(PostMedia, post_media)
mapper_registry.map_imperatively(UserToken, user_tokens)

async_engine = create_async_engine(DATABASE_URL, echo=True)
async_session = sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)

class DatabaseManager:
    async def connect(self):
        """Проверка подключения к БД"""
        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        print("✅ Подключение к PostgreSQL успешно")

    async def create_tables(self):
        """Создание всех таблиц"""
        async with async_engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        print("✅ Таблицы успешно созданы")

    async def drop_tables(self):
        """Удаление всех таблиц"""
        async with async_engine.begin() as conn:
            await conn.run_sync(metadata.drop_all)
        print("✅ Таблицы успешно удалены")

db_manager = DatabaseManager()