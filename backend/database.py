import databases
import ormar
import sqlalchemy
from datetime import datetime
from sqlalchemy.ext.asyncio import create_async_engine
from settings import settings

database = databases.Database(settings.POSTGRES_URL.replace("postgresql://", "postgresql+asyncpg://"))

# Асинхронное подключение
async_engine = create_async_engine(
    settings.POSTGRES_URL.replace("postgresql://", "postgresql+asyncpg://")
)

metadata = sqlalchemy.MetaData()  # контейнер для хранения описания таблиц

class BaseMeta(ormar.ModelMeta):
    metadata = metadata
    database = database


class User(ormar.Model):
    class Meta(BaseMeta):
        tablename = "users"

    id: int = ormar.Integer(primary_key=True)
    email: str = ormar.String(max_length=128, unique=True, nullable=False)
    username: str = ormar.String(max_length=128, unique=True, nullable=False)
    is_active: bool = ormar.Boolean(default=True, nullable=False)
    password_hash: str = ormar.String(max_length=128, unique=False, nullable=False)

class Session(ormar.Model):
    class Meta(BaseMeta):
        tablename = "sessions"

    id: str = ormar.String(max_length=50, primary_key=True)
    user: User = ormar.ForeignKey(User)
    started_at: datetime = ormar.DateTime(default=datetime.now)
    last_access: datetime = ormar.DateTime(default=datetime.now)
    ip_address: str = ormar.String(max_length=50)
    user_agent: str = ormar.String(max_length=200, nullable=True)

class TemporaryLink(ormar.Model):
    class Meta(BaseMeta):
        tablename = "temporary_links"

    id: str = ormar.String(max_length=100, primary_key=True)
    user: User = ormar.ForeignKey(User)
    token: str = ormar.String(max_length=200, unique=True)
    created_at: datetime = ormar.DateTime(default=datetime.now)
    expires_at: datetime = ormar.DateTime()
    is_used: bool = ormar.Boolean(default=False)

class Post(ormar.Model):
    class Meta(BaseMeta):
        tablename = "posts"

    id: str = ormar.String(max_length=50, primary_key=True)
    user: User = ormar.ForeignKey(User)
    text: str = ormar.Text()
    created_at: datetime = ormar.DateTime(default=datetime.now)

class PostMedia(ormar.Model):
    class Meta(BaseMeta):
        tablename = "post_media"

    id: str = ormar.String(max_length=50, primary_key=True)
    post: Post = ormar.ForeignKey(Post)
    file_type: str = ormar.String(max_length=20)  # 'image' или 'video'
    file_path: str = ormar.String(max_length=200)
    upload_date: datetime = ormar.DateTime(default=datetime.now)

class Hashtag(ormar.Model):
    class Meta(BaseMeta):
        tablename = "hashtags"

    id: int = ormar.Integer(primary_key=True)
    tag: str = ormar.String(max_length=50, unique=True)

#многие ко многим
class PostHashtag(ormar.Model):
    class Meta(BaseMeta):
        tablename = "post_hashtags"

    id: int = ormar.Integer(primary_key=True)
    post: Post = ormar.ForeignKey(Post)
    hashtag: Hashtag = ormar.ForeignKey(Hashtag)

class UserToken(ormar.Model):
    class Meta(BaseMeta):
        tablename = "user_tokens"

    id: int = ormar.Integer(primary_key=True)
    user: User = ormar.ForeignKey(User)
    service: str = ormar.String(max_length=20)  # 'telegram', 'vk', 'ok'
    token_type: str = ormar.String(max_length=20)  # 'bot', 'chat', 'group', 'user'
    token_value: str = ormar.String(max_length=200)
    last_updated: datetime = ormar.DateTime(default=datetime.now)

async def check_db_connection():
    try:
        async with async_engine.connect() as conn:
            print("✅ Асинхронное подключение к PostgreSQL успешно")
        await database.connect()
    except Exception as e:
        print(f"❌ Ошибка асинхронного подключения: {e}")
        raise

async def create_tables():
    try:
        async with async_engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        print("✅ Таблицы успешно созданы")
    except Exception as e:
        print(f"❌ Ошибка при создании таблиц: {e}")
        raise
