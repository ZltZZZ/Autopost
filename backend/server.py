import os
import uuid
import logging
import json
from contextlib import asynccontextmanager
from typing import Annotated, List
from fastapi import FastAPI, Response, Cookie, Request, UploadFile, Form, HTTPException, File
from keycloak import KeycloakOpenID, KeycloakAdmin
from starlette.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware 
from datetime import datetime, timedelta
from sqlalchemy import text

import database
from settings import settings

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Обработка событий жизненного цикла приложения"""
    await database.db_manager.connect()
    await database.db_manager.create_tables()
    yield

app = FastAPI(lifespan=lifespan,
    title="AutoPost API",
    description="API for automatic posting to social networks",
    openapi_tags=[{
        "name": "profiles",
        "description": "Operations with profiles"
    }, {
        "name": "posts",
        "description": "Operations with posts in profiles"
    }])

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://autopost.work.gd"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)
app.state.max_request_size = 100 * 1024 * 1024  # 100 MB

# Keycloak config
keycloak_openid = KeycloakOpenID(
    server_url=settings.KEYCLOAK_URL,
    realm_name=settings.REALM,
    client_id=settings.CLIENT_ID,
    client_secret_key=settings.CLIENT_SECRET_KEY
)

options = {"verify_signature": True, "verify_aud": False, "verify_exp": True}

def decode_token(token: str):
    KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
    try:
        token_info = keycloak_openid.decode_token(token, key=KEYCLOAK_PUBLIC_KEY, options=options)
    except Exception as e:
        logger.error(e)
        token_info = None
    return token_info

@app.get("/api/auth/check",  tags=["auth"])
async def check_auth(access_token: Annotated[str, Cookie()] = ""):
    """Проверка токена"""
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

@app.get("/api/auth/logout", tags=["auth"])
async def logout(refresh_token: Annotated[str | None, Cookie()] = None):
    """Выход и перенаправление на страницу аутентификации"""
    keycloak_openid.logout(refresh_token)
    response = RedirectResponse("/")
    response.set_cookie(key="access_token", value="")
    response.set_cookie(key="refresh_token", value="")
    return response

@app.get("/api/auth/callback",  tags=["auth"])
async def auth_callback(code: str = "", request: Request = None):
    """Определение токена"""
    access_token = keycloak_openid.token(
        grant_type='authorization_code',
        code=code,
        redirect_uri=settings.REDIRECT_URL)
    
    response = RedirectResponse("/")
    response.set_cookie(key="access_token", value=access_token["access_token"])
    response.set_cookie(key="refresh_token", value=access_token["refresh_token"])
    return response

async def get_current_user(access_token: Annotated[str, Cookie()] = "") -> database.User:
    """Проверка авторизации через куки и получение данных текущего пользователя"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    async with database.db_manager.get_session() as session:
        
        # Получаем пользователя
        result = await session.execute(
            text("SELECT * FROM users WHERE id = :user_id"),
            {"user_id": user_id}
        )
        user_data = result.mappings().fetchone() 
        if not user_data:
            raise HTTPException(status_code=404, detail="User not found")
        user_dict = dict(user_data)

        return database.User(
            id=user_dict['id'],
            username=user_dict['username'],
            email=user_dict['email'],
            is_active=user_dict['is_active']
        )


@app.get("/api/profile", tags=["profile"])
async def profile_page(access_token: Annotated[str, Cookie()] = ""):
    """Возвращает id профиля(если не аутентифицирован -> на страницу аутентификации)
       Проверяет инфу о пользователе в базе, если нет такого пользователя, извлекает нужные данные из токена
    """
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    
    username = token_info.get('preferred_username')
    email = token_info.get('email')
    #auth_time = token_info.get('auth_time')#время последней аутентификации пользователя
    #name = token_info.get('name') #полное имя (first + last name)
    profile_id = token_info.get('sub')  # Уникальный ID пользователя

    # Получаем сессию через async_sessionmaker
    async with database.async_session() as session:
        try:
            async with session.begin():
                # Проверяем существование пользователя
                existing_user = await session.get(database.User, profile_id) # поиск по первичному ключу
                
                if existing_user is None:
                    # Создаем нового пользователя
                    new_user = database.User(
                        id=profile_id,
                        username=username,
                        email=email,
                        is_active=True
                    )
                    session.add(new_user)
                    await session.commit()
                    return {"message": "User created", "user_id": new_user.id}
                
        except Exception as e:
            await session.rollback()
            raise HTTPException(status_code=400, detail=str(e))
    
    return {"message": "User exists", "user_id": profile_id}

@app.get("/api/profile/{profile_id}", tags=["profile"])
async def get_profile_data(profile_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить данные конкретного профиля"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    
    user_id = token_info.get('sub')

    async with database.async_session() as session:
        async with session.begin():
            result = await session.execute(
                text("SELECT * FROM users WHERE id = :user_id"),
                {"user_id": user_id}
            )
            if not result:
                raise HTTPException(status_code=404, detail="User not found")
            user_info = result.mappings().fetchone()

        # Получаем существующие сессии
            result = await session.execute(
                text("SELECT * FROM sessions WHERE id = :user_id"),
                {"user_id": user_id}
            )
            user_sessions = result.mappings().fetchone()

    return {
        "user_info": [
            { 
                "username": user_info.username,
                "email": user_info.email
            }
        ],
        "user_sessions": [
            {
                "id": session.id, #id сессии! 
                "started_at": session.started_at,
                "last_access": session.last_access,
                "ip_address": session.ip_address
            }
            for session in user_sessions
        ],
        
    }

@app.put("/api/profile/{profile_id}", tags=["profile"])
async def update_profile(profile_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Обновить профиль"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass

@app.delete("/api/profile/{profile_id}", tags=["profile"])
async def delete_profile(profile_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Удалить профиль"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass

@app.get("/api/profile/{profile_id}/sessions", tags=["profile"])
async def get_sessions(profile_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить все активные сессии данного профиля"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    
    user = await database.User.objects.get_or_none(id = token_info.get('sub'))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    try:
        # Получаем user_id из токена
        user_id = token_info.get("sub")
        keycloak_admin = KeycloakAdmin(
    server_url="http://0.0.0.0:8080",
    username=settings.KEYCLOAK_ADMIN,
    password=settings.KEYCLOAK_ADMIN_PASSWORD,
    realm_name=settings.REALM,
    client_id=settings.CLIENT_ID,
    verify=False,  # отключаем проверку для dev
    auto_refresh_token=['get', 'put', 'post', 'delete']
)
        # Получаем список сессий через Admin API
        sessions = keycloak_admin.get_user_sessions(user_id)
       
        # Форматируем ответ
        formatted_sessions = []
        for session in sessions:
            formatted_sessions.append({
                "session_id": session.get("id"),
                "ip_address": session.get("ipAddress"),
                "started_at": datetime.fromtimestamp(session.get("start")/1000).isoformat(),
                "last_accessed": datetime.fromtimestamp(session.get("lastAccess")/1000).isoformat(),
               "expires_at": datetime.fromtimestamp(session.get("expiration")/1000).isoformat(),
                "client_id": session.get("clientId"),
                "current": session.get("id") == token_info.get("sid")  # текущая ли сессия
            })
        
        return {"sessions": formatted_sessions}
    
    except Exception as e:
        logger.error(f"Failed to get user sessions: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve sessions")

@app.delete("/api/profile/{profile_id}/sessions/{session_id}", tags=["profile"])
async def terminate_session(
    profile_id: str,
    #session_id: str = Form(...),
    access_token: Annotated[str, Cookie()] = ""
):
    """Завершить конкретную сессию"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)

    user = await database.User.objects.get_or_none(id = token_info.get('sub'))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    
    #try:
    #    # Получаем user_id из токена
    #    user_id = token_info.get("sub")
        
    #    # Завершаем сессию
    #    keycloak_admin.revoke_user_session(user_id, session_id)
        
    #    return {"status": "success", "message": "Session terminated"}
    
    #except Exception as e:
    #    logger.error(f"Failed to revoke session: {str(e)}")
    #    raise HTTPException(status_code=500, detail="Failed to revoke session")


@app.post("/api/profile/{profile_id}/temp-links", tags=["profile"])
async def create_temp_link(
    profile_id: str,
    duration: int = Form(...),          #продолжительность действия временной ссылки в минутах
    access_token: Annotated[str, Cookie()] = ""
):
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)

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
        )
        
        return {
            "success": True,
            "link": f"{settings.BASE_URL}/temp/{token}",
            "expires_at": expires_at.isoformat()
        }
    except Exception as e:
        logger.error(f"Error creating temporary link: {e}")
        raise HTTPException(status_code=500, detail="Failed to create link")

@app.get("/api/profile/{profile_id}/temp-links", tags=["profile"])
async def get_temp_links(profile_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить все временные ссылки пользователя"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass

@app.delete("/api/profile/{profile_id}/temp-links/{link_id}", tags=["profile"])
async def revoke_temp_link(
    profile_id: str,
    #link_id: str = Form(...),
    access_token: Annotated[str, Cookie()] = ""
    ):
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    
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


@app.get("/api/profile/{profile_id}/posts", tags=["posts"])
async def get_posts(profile_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить все посты (с полнотекстовым поиском)"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass

@app.get("/api/profile/{profile_id}/posts/{post_id}", tags=["posts"])
async def get_post(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить конкретный пост"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass

@app.post("/api/profile/{profile_id}/posts/", tags=["posts"])
async def create_post(
        profile_id: str,
        text: str = Form(...),
        hashtags: List[str] = Form([]),
        images: List[UploadFile] = File([]),
        videos: List[UploadFile] = File([]), 
        access_token: Annotated[str, Cookie()] = ""
):
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    
    saved_media = []
    os.makedirs("media", exist_ok=True)

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

@app.put("/api/profile/{profile_id}/posts/{post_id}", tags=["posts"])
async def update_post(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Обновить существующий пост"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass
async def update_tokens(
    telegramBotToken: str = Form(None),
    telegramChatId: str = Form(None),
    vkGroupToken: str = Form(None),
    vkUserToken: str = Form(None),
    okGroupToken: str = Form(None),
    access_token: Annotated[str, Cookie()] = ""
):
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    
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


@app.delete("/api/profile/{profile_id}/posts/{post_id}", tags=["posts"])
async def delete_post(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Удалить пост"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass

@app.get("/api/profile/{profile_id}/posts/{post_id}/hashtags/", tags=["posts"])
async def get_post_hashtags(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить все хэштеги поста"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass

@app.post("/api/profile/{profile_id}/posts/{post_id}/hashtags/generate", tags=["posts"])
async def generate_post_hashtags(profile_id: str, post_id: str, text: str = Form(...), access_token: Annotated[str, Cookie()] = ""):
    """Сгенерировать хэштеги для поста"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    
    words = text.lower().split()
    hashtags = [f"#{word}" for word in words if len(word) > 3][:5]
    return {"hashtags": hashtags}

@app.put("/api/profile/{profile_id}/posts/{post_id}/hashtags/", tags=["posts"])
async def change_post_hashtags(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Отредактировать хэштеги поста"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass

@app.delete("/api/profile/{profile_id}/posts/{post_id}/hashtags/", tags=["posts"])
async def clean_post_hashtags(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Очистить хэштеги поста"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass

@app.post("/api/profile/{profile_id}/posts/{post_id}/media", tags=["posts"])
async def upload_media(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = "", file: UploadFile = File(...)):
    """Загрузить медиафайл для поста"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass

@app.get("/api/profile/{profile_id}/posts/{post_id}/media", tags=["posts"])
async def get_post_media(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить все медиафайлы поста"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass

@app.delete("/api/profile/{profile_id}/posts/{post_id}/media/{media_id}", tags=["posts"])
async def delete_media(profile_id: str, post_id: str, media_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Удалить медиафайл"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass

@app.options("/api/{path:path}")
async def options_handler():
    return Response(headers={
        "Access-Control-Allow-Origin": "http://autopost.work.gd",
        "Access-Control-Allow-Methods": "POST, GET, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie",
        "Access-Control-Allow-Credentials": "true"
    })

openapi_schema = app.openapi()
with open("openapi.json", "w") as f:
    json.dump(openapi_schema, f)