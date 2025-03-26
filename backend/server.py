import logging
import os
from contextlib import asynccontextmanager
from typing import Annotated, List, Dict
from fastapi import FastAPI, Response, Cookie, Request, UploadFile, Form, HTTPException, File
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from keycloak import KeycloakOpenID
from starlette.responses import RedirectResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel
import uuid
from fastapi.middleware.cors import CORSMiddleware 
import random
import string

from datetime import datetime, timedelta
from settings import settings
import database

async def populate_test_data():
    # Проверяем, есть ли уже данные в базе
    if await database.User.objects.count() > 0:
        return 
    
    logger.info("Populating database with test data...")
    
    # Создаем пользователей
    users = [
        await database.User.objects.create(
            email=f"user{i}@example.com",
            username=f"user{i}",
            is_active=True,
            password_hash=f"hashed_password_{i}"
        )
        for i in range(1, 6)
    ]
    
    # Создаем сессии
    for user in users:
        await database.Session.objects.create(
            id=str(uuid.uuid4()),
            user=user,
            started_at=datetime.now() - timedelta(days=1),
            last_access=datetime.now(),
            ip_address=f"192.168.1.{users.index(user) + 1}",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        )
    
    # Создаем временные ссылки
    for user in users:
        await database.TemporaryLink.objects.create(
            id=str(uuid.uuid4()),
            user=user,
            token=f"temp_token_{users.index(user) + 1}",
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=1),
            is_used=False
        )
    
    # Создаем посты
    posts = []
    for user in users:
        for j in range(1, 4):  # По 3 поста на пользователя
            post = await database.Post.objects.create(
                id=str(uuid.uuid4()),
                user=user,
                text=f"Это тестовый пост #{j} от пользователя {user.username}",
                created_at=datetime.now() - timedelta(days=j)
            )
            posts.append(post)
    
    # Создаем медиа для постов
    for post in posts:
        media_type = "image" if posts.index(post) % 2 == 0 else "video"
        await database.PostMedia.objects.create(
            id=str(uuid.uuid4()),
            post=post,
            file_type=media_type,
            file_path=f"/media/{post.id}/{media_type}_{posts.index(post) + 1}.{'jpg' if media_type == 'image' else 'mp4'}",
            upload_date=post.created_at
        )
    
    # Создаем хэштеги
    hashtags = [
        await database.Hashtag.objects.create(tag=f"hashtag_{i}") 
        for i in ["test", "example", "social", "network", "demo"]
    ]
    
    # Связываем посты с хэштегами
    for post in posts:
        for hashtag in hashtags[:2]:  # Добавляем первые 2 хэштега к каждому посту
            await database.PostHashtag.objects.create(
                post=post,
                hashtag=hashtag
            )
    
    # Создаем токены пользователей
    services = ["telegram", "vk", "ok"]
    token_types = ["bot", "chat", "group", "user"]
    
    for user in users:
        for service in services:
            await database.UserToken.objects.create(
                user=user,
                service=service,
                token_type=token_types[users.index(user) % len(token_types)],
                token_value=f"{service}_token_{user.username}"
            )
    
    logger.info("Test data populated successfully")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """обработка событий жизненного цикла"""
    await database.check_db_connection()
    await database.create_tables()

    # Заполнение тестовыми данными
    await populate_test_data()
    yield

    if database.is_connected:
        await database.disconnect()

logger = logging.getLogger(__name__)
app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://192.168.50.77", "http://172.17.7.12"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

app.state.max_request_size = 100 * 1024 * 1024  # 100MB

# Keycloak config
keycloak_openid = KeycloakOpenID(
    server_url=settings.KEYCLOAK_URL,
    realm_name=settings.REALM,
    client_id=settings.CLIENT_ID,
    client_secret_key=settings.CLIENT_SECRET_KEY
)

options = {"verify_signature": True, "verify_aud": False, "verify_exp": True}

# Глобальное хранилище временных ссылок (в реальном приложении используйте БД)
#temporary_links = {}
#posts_storage = {}
#user_data = {
#	"tokens": {}
#}

# Генерируем пример данных активных сессий
#active_sessions = [
#    {
#        "id": "session_1",
#        "started": (datetime.now() - timedelta(days=2)).isoformat(),
#        "last_access": (datetime.now() - timedelta(minutes=15)).isoformat(),
#        "ip_address": "192.168.1.100",
#    },
#    {
#        "id": "session_2",
#        "started": (datetime.now() - timedelta(hours=5)).isoformat(),
#        "last_access": (datetime.now() - timedelta(minutes=2)).isoformat(),
#        "ip_address": "93.184.216.34",
#    }
#]


def decode_token(token: str):
    KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
    try:
        token_info = keycloak_openid.decode_token(token, key=KEYCLOAK_PUBLIC_KEY, options=options)
    except Exception as e:
        logger.error(e)
        token_info = None
    return token_info


@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, access_token: Annotated[str, Cookie()] = ""):
    if not access_token or not decode_token(access_token):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)

    return FileResponse("frontend/app/profile.html")


@app.options("/api/{path:path}")
async def options_handler():
    return Response(headers={
        "Access-Control-Allow-Origin": "http://192.168.50.77",
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie",
        "Access-Control-Allow-Credentials": "true"
    })


@app.get("/api/profile/data")
async def get_profile_data(access_token: Annotated[str, Cookie()] = ""):
    if not access_token or not (token_info := decode_token(access_token)):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = await database.User.objects.get_or_none(email=token_info.get("email"))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Получаем активные временные ссылки
    active_link = await database.TemporaryLink.objects.filter(
        user=user,
        expires_at__gte=datetime.now(),
        is_used=False
    ).order_by("-created_at").first()

    # Получаем активные сессии
    active_sessions = await database.Session.objects.filter(
        user=user,
        last_access__gte=datetime.now() - timedelta(hours=24)
    ).all()

    # Получаем токены пользователя
    user_tokens = await database.UserToken.objects.filter(user=user).all()
    tokens_dict = {
        "telegramBotToken": "",
        "telegramChatId": "",
        "vkGroupToken": "",
        "vkUserToken": "",
        "okGroupToken": "",
    }
    
    for token in user_tokens:
        service_key = f"{token.service}{token.token_type.capitalize()}Token"
        if service_key in tokens_dict:
            tokens_dict[service_key] = token.token_value

    return {
        "tokens": tokens_dict,
        "active_sessions": [
            {
                "id": session.id,
                "started": session.started_at.isoformat(),
                "last_access": session.last_access.isoformat(),
                "ip_address": session.ip_address
            }
            for session in active_sessions
        ],
        "temporary_link": {
            "link": f"{settings.BASE_URL}/temp/{active_link.token}" if active_link else None,
            "expires_at": active_link.expires_at.isoformat() if active_link else None
        } if active_link else None
    }


@app.post("/api/generate_hashtags")
async def generate_hashtags(text: str = Form(...), access_token: Annotated[str, Cookie()] = ""):
    if not access_token or not decode_token(access_token):
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Simple hashtag generation logic
    words = text.lower().split()
    hashtags = [f"#{word}" for word in words if len(word) > 3][:5]
    return {"hashtags": hashtags}


@app.post("/api/create_post")
async def create_post(
        text: str = Form(...),
        hashtags: List[str] = Form([]),
        images: List[UploadFile] = File([]),
        videos: List[UploadFile] = File([]),  # Добавляем поддержку видео
        access_token: Annotated[str, Cookie()] = ""
):
    if not access_token or not decode_token(access_token):
        raise HTTPException(status_code=401, detail="Not authenticated")

    saved_media = []
    os.makedirs("media", exist_ok=True)

    # Сохраняем изображения
    for image in images:
        if image.content_type not in ["image/jpeg", "image/png", "image/gif"]:
            continue

        file_ext = os.path.splitext(image.filename)[1]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"image_{timestamp}_{uuid.uuid4().hex}{file_ext}"
        file_path = os.path.join("media", filename)

        with open(file_path, "wb") as buffer:
            buffer.write(await image.read())

        saved_media.append({"type": "image", "filename": filename})

    # Сохраняем видео
    for video in videos:
        if video.content_type not in ["video/mp4", "video/webm", "video/ogg"]:
            continue

        file_ext = os.path.splitext(video.filename)[1]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"video_{timestamp}_{uuid.uuid4().hex}{file_ext}"
        file_path = os.path.join("media", filename)

        with open(file_path, "wb") as buffer:
            buffer.write(await video.read())

        saved_media.append({"type": "video", "filename": filename})

    post_id = str(uuid.uuid4())
    posts_storage[post_id] = {
        "text": text,
        "hashtags": hashtags,
        "media": saved_media  # Объединенный список медиафайлов
    }

    return {"success": True}


@app.post("/api/update_tokens")
async def update_tokens(
    telegramBotToken: str = Form(None),
    telegramChatId: str = Form(None),
    vkGroupToken: str = Form(None),
    vkUserToken: str = Form(None),
    okGroupToken: str = Form(None),
    access_token: Annotated[str, Cookie()] = ""
):
    if not access_token or not (token_info := decode_token(access_token)):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = await database.User.objects.get_or_none(email=token_info.get("email"))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    updates = {
        ("telegram", "bot"): telegramBotToken,
        ("telegram", "chat"): telegramChatId,
        ("vk", "group"): vkGroupToken,
        ("vk", "user"): vkUserToken,
        ("ok", "group"): okGroupToken,
    }

    try:
        for (service, token_type), token_value in updates.items():
            if token_value is not None:
                token, _ = await database.UserToken.objects.update_or_create(
                    user=user,
                    service=service,
                    token_type=token_type,
                    defaults={
                        "token_value": token_value,
                        "last_updated": datetime.now()
                    }
                )
        return {"success": True}
    except Exception as e:
        logger.error(f"Error updating tokens: {e}")
        raise HTTPException(status_code=500, detail="Failed to update tokens")


@app.post("/api/change_password")
async def change_password(
        new_password: str = Form(...),
        access_token: Annotated[str, Cookie()] = ""
):
    if not access_token or not decode_token(access_token):
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Update password (in real app, use Keycloak admin API)
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Can't update password")


@app.post("/api/terminate_session")
async def terminate_session(
    session_id: str = Form(...),
    access_token: Annotated[str, Cookie()] = ""
):
    if not access_token or not (token_info := decode_token(access_token)):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = await database.User.objects.get_or_none(email=token_info.get("email"))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        session = await database.Session.objects.get_or_none(id=session_id, user=user)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        await session.delete()
        return {"success": True}
    except Exception as e:
        logger.error(f"Error terminating session: {e}")
        raise HTTPException(status_code=500, detail="Failed to terminate session")


#@app.post("/api/generate_temporary_link")
#async def generate_temporary_link(
#        duration: int = Form(...),  # Длительность в минутах
#        access_token: Annotated[str, Cookie()] = ""
#):
#    if not access_token or not decode_token(access_token):
#        raise HTTPException(status_code=401, detail="Not authenticated")

    # Рассчитываем время истечения
#    expires_at = datetime.now() + timedelta(minutes=duration)

    # Сохраняем в хранилище (в реальном приложении используйте БД)
#    temporary_links[access_token] = {
#        "expires_at": expires_at.isoformat(),
#        "created_at": datetime.now().isoformat()
#    }

    # Возвращаем ссылку (в реальном приложении используйте ваш домен)
#    return {
#        "success": True,
#        "link": f"http://localhost/temp/{access_token}",
#        "expires_at": expires_at.isoformat()
#    }

@app.post("/api/generate_temporary_link")
async def generate_temporary_link(
    duration: int = Form(...),          #продолжительность действия временной ссылки в минутах
    access_token: Annotated[str, Cookie()] = ""
):
    if not access_token or not (token_info := decode_token(access_token)):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = await database.User.objects.get_or_none(email=token_info.get("email"))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    expires_at = datetime.now() + timedelta(minutes=duration)  #время истечения ссылки
    token = str(uuid.uuid4())  #генерация токена

    try:
        await database.TemporaryLink.objects.create( # сохраняем в базу
            token=token,
            user=user,
            expires_at=expires_at,
            is_used=False
        )
        
        return {
            "success": True,
            "link": f"{settings.BASE_URL}/temp/{token}",
            "expires_at": expires_at.isoformat()
        }
    except Exception as e:
        logger.error(f"Error creating temporary link: {e}")
        raise HTTPException(status_code=500, detail="Failed to create link")

@app.post("/api/revoke_temporary_link")
async def revoke_temporary_link(
    link_id: str = Form(...),
    access_token: Annotated[str, Cookie()] = ""
):
    if not access_token or not (token_info := decode_token(access_token)):
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = await database.User.objects.get_or_none(email=token_info.get("email"))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        link = await database.TemporaryLink.objects.get_or_none(id=link_id, user=user)
        if not link:
            raise HTTPException(status_code=404, detail="Link not found")

        await link.delete()
        return {"success": True}
    except Exception as e:
        logger.error(f"Error revoking temporary link: {e}")
        raise HTTPException(status_code=500, detail="Failed to revoke link")

@app.post("/api/suggest_hashtags")
async def suggest_hashtags(
        prefix: str = Form(...),
        access_token: Annotated[str, Cookie()] = ""
):
    if not access_token or not decode_token(access_token):
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Генерация случайных предложений
    num_suggestions = random.randint(1, 10)
    suggestions = []

    for _ in range(num_suggestions):
        # Генерируем случайное продолжение (1-10 символов)
        suffix_length = random.randint(1, 10)
        suffix = ''.join(random.choices(string.ascii_lowercase, k=suffix_length))
        suggestions.append(f"{prefix}{suffix}")

    return {"suggestions": suggestions}


@app.get("/auth/check")
def check_auth(access_token: Annotated[str, Cookie()] = ""):
    if access_token:
        token_info = decode_token(access_token)
        redirect = token_info is None
    else:
        redirect = True
    url = keycloak_openid.auth_url(scope="openid+profile", redirect_uri=settings.REDIRECT_URL)
    return {
        "url": url,
        "redirect": redirect
    }


@app.get("/auth/logout")
def logout(refresh_token: Annotated[str | None, Cookie()] = None):
    keycloak_openid.logout(refresh_token)
    response = RedirectResponse("/")
    response.set_cookie(key="access_token", value="")
    response.set_cookie(key="refresh_token", value="")
    return response


@app.get("/auth/callback")
def auth_callback(code: str = "", ):
    access_token = keycloak_openid.token(
        grant_type='authorization_code',
        code=code,
        redirect_uri=settings.REDIRECT_URL)
    response = RedirectResponse("/")
    response.set_cookie(key="access_token", value=access_token["access_token"])
    response.set_cookie(key="refresh_token", value=access_token["refresh_token"])
    return response
