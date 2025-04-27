import base64
import uuid
import re
import requests
import logging
import httpx
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Annotated, List
from fastapi import FastAPI, Response, Cookie, Request, UploadFile, Form, HTTPException, File
from keycloak import KeycloakOpenID, KeycloakAdmin
from starlette.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware 
from datetime import datetime, timedelta, timezone
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from sqlalchemy import text, select, join, delete, update, func
from fastapi import UploadFile, File
from collections import Counter
from zoneinfo import ZoneInfo

import database
from settings import settings

logger = logging.getLogger(__name__)
MOSCOW_TZ = ZoneInfo("Europe/Moscow")

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
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Cookie"],
    allow_credentials=True,
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


@app.get("/api/profile", tags=["profile"])
async def profile_page(access_token: Annotated[str, Cookie()] = ""):
    """Получить id профиля"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    profile_id = token_info.get('sub') 

    async with database.async_session() as session:
        try:
            async with session.begin():
                existing_user = await session.get(database.User, profile_id) # поиск по первичному ключу
                
                if existing_user is None:
                    username = token_info.get('preferred_username')
                    email = token_info.get('email')

                    new_user = database.User(
                        id=profile_id,
                        username=username,
                        email=email,
                    )
                    session.add(new_user)
                    await session.commit()
                    return {"message": "User created", "user_id": new_user.id}
                
        except Exception as e:
            await session.rollback()
            raise HTTPException(status_code=400, detail=str(e))
    
    return {"message": "User exists", "user_id": profile_id}

@app.get("/api/profile/{profile_id}/posts", tags=["posts"])
async def get_posts(profile_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить все посты пользователя"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")

    async with database.async_session() as session:
        try:
            async with session.begin():
                result = await session.execute(
                    text("SELECT * FROM posts WHERE user_id = :user_id"),
                    {"user_id": user_id}
                )
                posts_data = result.mappings().fetchone() 
                if not posts_data:
                    return {"message": "Post not exists", "post_id": -1}
                return {"message": "Post exists", "post_id": posts_data["id"]}
        
        except Exception as e:
            await session.rollback()
            raise HTTPException(status_code=400, detail=str(e)) 
        
#http://autopost.work.gd:8080/api/profile/30b84fcf-9ccc-48d4-bbe9-f1631b5a9c8e/posts
@app.post("/api/profile/{profile_id}/posts", tags=["posts"])
async def create_post(profile_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Создание поста, если есть - вернуть его id"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")

    async with database.async_session() as session:
        try:
            async with session.begin():
                new_post = database.Post(
                        user_id=user_id,
                        text="",
                        post_at=None,
                )
                session.add(new_post)
                await session.flush()
                await session.commit()
                return {"message": "New post", "post_id": new_post.id}
            
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Error creating post: {str(e)}"
            )


@app.post("/api/profile/{profile_id}/posts/{post_id}", tags=["posts"])
async def publish_post(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Опубликовать пост"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")

    async with database.async_session() as session:
        try:
            async with session.begin():
                post = await session.get(database.Post, post_id)
                if not post:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Post with id {post_id} not found"
                    )
                hashtags_query = select(database.PostHashtag.hashtag).where(
                    database.PostHashtag.post_id == post_id
                )
                hashtags_result = await session.execute(hashtags_query)
                hashtags = [f"#{row[0]}" for row in hashtags_result.fetchall()]

                message = post.text
                if hashtags:
                    message += "\n\n" + " ".join(hashtags)
                MESSAGE = message

                tokens_query = select(
                    database.UserToken.service,
                    database.UserToken.token_type,
                    database.UserToken.token_value
                ).where(
                    database.UserToken.user_id == user_id
                )
                tokens_result = await session.execute(tokens_query)
                tokens = tokens_result.fetchall()

                user_tokens = {}
                for service, token_type, token_value in tokens:
                    if service not in user_tokens:
                        user_tokens[service] = {}
                    user_tokens[service][token_type] = token_value

                if "telegram" in user_tokens and "bot" in user_tokens["telegram"] and "chat" in user_tokens["telegram"]:
                    tg_bot_token = user_tokens["telegram"]["bot"]
                    tg_chat_id = user_tokens["telegram"]["chat"]
                    
                    if not tg_bot_token or not tg_chat_id:
                        raise HTTPException(
                            status_code=400,
                            detail="Telegram bot token or chat ID not configured"
                        )

                    tg_url = f'https://api.telegram.org/bot{tg_bot_token}/sendMessage'
                    params = {
                        'chat_id': tg_chat_id,
                        'text': MESSAGE
                    }
                    requests.post(tg_url, params=params)

                if "vk" in user_tokens and "group" in user_tokens["vk"]:
                    vk_group_token = user_tokens["vk"]["group"]
                    url = 'https://api.vk.com/method/wall.post'
                    params = {
                        'message': MESSAGE,
                        'access_token': vk_group_token,
                        'v': '5.131'
                    }
                    requests.post(url, params=params)

                if "vk" in user_tokens and "user" in user_tokens["vk"]:
                    vk_user_token = user_tokens["vk"]["user"]
                    url = 'https://api.vk.com/method/wall.post'
                    params = {
                        'message': MESSAGE,
                        'access_token': vk_user_token,
                        'v': '5.131'
                    }
                    requests.post(url, params=params)

                if "ok" in user_tokens and "group" in user_tokens["ok"]:
                    ok_group_token = user_tokens["ok"]["group"]
                    # ok_url = "https://api.ok.ru/fb.do"
                    # params = {
                    #     'method': 'posting.get',
                    #     'access_token': ok_group_token,
                    #     'message': MESSAGE,
                    #     'application_key': 'YOUR_APP_KEY',
                    #     'format': 'json'
                    # }
                    # requests.post(ok_url, params=params)
                    pass

        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Error posting post: {str(e)}"
            )
        
    return {"message": "success"}

@app.delete("/api/profile/{profile_id}/posts/{post_id}", tags=["posts"])
async def delete_post(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Удалить пост"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")
    pass
    #async with database.async_session() as session:
    #    try:
    #        async with session.begin():
    #            post = await session.get(database.Post, post_id)
    #            if not post:
    #                raise HTTPException(
    #                    status_code=404,
    #                    detail=f"Post with id {post_id} not found"
    #                )
    #            await session.execute(
    #                delete(database.PostMedia)
    #                .where(database.PostMedia.post_id == post_id)
    #            )
    #            
    #            await session.execute(
    #                delete(database.PostHashtag)
    #                .where(database.PostHashtag.post_id == post_id)
    #            )
    #
    #            await session.delete(post)                
    #        return {"message": f"Post {post_id} deleted successfully"}
                
            
    #    except Exception as e:
    #        await session.rollback()
    #        raise HTTPException(
    #            status_code=400,
    #            detail=f"Error delete post {post_id}: {str(e)}"
    #        )

@app.get("/api/profile/{profile_id}/posts/{post_id}/text", tags=["posts"])
async def get_text(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить текст поста"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")
    
    async with database.async_session() as session:
        try:
            async with session.begin():
                post = await session.get(database.Post, post_id)
                return {"text": post.text}
            
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Error get text by post {post_id}: {str(e)}"
            )

@app.put("/api/profile/{profile_id}/posts/{post_id}/text", tags=["posts"])
async def update_text(profile_id: str, post_id: str, text_data: dict, access_token: Annotated[str, Cookie()] = ""):
    """Обновить существующий текст поста"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")
    
    async with database.async_session() as session:
        try:
            async with session.begin():
                post = await session.get(database.Post, post_id)
                if not post:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Post with id {post_id} not found"
                    )

                post.text = text_data["text"]
                await session.commit()
            
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Error update text by post {post_id}: {str(e)}"
            )
        
@app.get("/api/profile/{profile_id}/posts/{post_id}/hashtags", tags=["posts"])
async def get_post_hashtags(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить все хэштеги поста"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")
    
    async with database.async_session() as session:
        try:
            async with session.begin():
                post = await session.get(database.Post, post_id)
                if not post:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Post with id {post_id} not found"
                    )

                stmt = (
                select(database.PostHashtag.hashtag)
                .where(database.PostHashtag.post_id == post_id)
                )
                result = await session.execute(stmt)
                hashtags = result.scalars().all()

                return {
                    "hashtags": hashtags
                }    
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Error get hashtags by post {post_id}: {str(e)}"
            )
        
@app.put("/api/profile/{profile_id}/posts/{post_id}/hashtags", tags=["posts"])
async def update_post_hashtags(profile_id: str, post_id: str, hashtags_data: dict, access_token: Annotated[str, Cookie()] = ""):
    """Обновить хэштеги поста"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail="Error: Access rights error")
    
    async with database.async_session() as session:
        try:
            async with session.begin():
                post = await session.get(database.Post, post_id)
                if not post:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Post with id {post_id} not found"
                    )

                existing_hashtags_result = await session.execute(
                    select(database.PostHashtag)
                    .where(database.PostHashtag.post_id == post_id)
                )
                existing_hashtags = existing_hashtags_result.scalars().all()
                existing_tags = {ht.hashtag for ht in existing_hashtags}

                new_tags = [tag.strip("#").lower() for tag in hashtags_data.get("hashtags", [])]
                new_tags = [tag for tag in new_tags if tag] 

                for hashtag in existing_hashtags:
                    if hashtag.hashtag not in new_tags:
                        await session.delete(hashtag)

                added_hashtags = []
                for tag in new_tags:
                    if tag not in existing_tags:
                        hashtag = database.PostHashtag(
                            post_id=post_id,
                            hashtag=tag,
                        )
                        session.add(hashtag)
                        added_hashtags.append(tag)

                await session.commit()
                
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Error updating hashtags for post {post_id}: {str(e)}"
            )

async def fulltext_search_hashtags(session, post_text: str, prefix: str, limit: int = 5) -> List[str]:
    """Поиск подходящих хэштегов по префиксу с использованием полнотекстового поиска"""
    # Ищем слова в тексте, начинающиеся с префикса (регистронезависимо)
    query = """
        WITH words AS (
            SELECT regexp_split_to_table(lower(:post_text), '[^а-яёa-z0-9]') AS word
        ),
        filtered_words AS (
            SELECT DISTINCT word 
            FROM words 
            WHERE word LIKE :prefix || '%' 
            AND length(word) > 2
            AND word NOT IN ('это', 'как', 'для', 'что', 'который', 'for', 'this', 'which', 'how')
        )
        SELECT word 
        FROM filtered_words
        ORDER BY word
        LIMIT :limit
    """
    
    result = await session.execute(
        text(query),
        {
            'post_text': post_text,
            'prefix': prefix.lower(),
            'limit': limit
        }
    )
    
    return [row[0] for row in result.fetchall()]

@app.post("/api/profile/{profile_id}/posts/{post_id}/suggest_hashtags")
async def suggest_hashtags(profile_id: str, post_id: str, prefix: str = Form(...), access_token: Annotated[str, Cookie()] = ""
):
    """Предложить хэштеги по префиксу"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")
    
    async with database.async_session() as session:
        try:
            async with session.begin():
                post = await session.get(database.Post, post_id)
                if not post:
                    raise HTTPException(status_code=404, detail="Post not found")
        
                post_text = post.text.lower()
                prefix = prefix.lower()

                suggestions = await fulltext_search_hashtags(
                    session=session,
                    post_text=post.text,
                    prefix=prefix
                )

                return {"suggestions": suggestions}

        except Exception as e:
            logger.error(f"Hashtag suggestion error: {str(e)}")
            return []

@app.get("/api/profile/{profile_id}/posts/{post_id}/media", tags=["posts"])
async def get_id_media(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить все id медиафайлов поста"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")
    
    async with database.async_session() as session:
        try:
            async with session.begin():
                post = await session.get(database.Post, post_id)
                if not post:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Post with id {post_id} not found"
                    )
                
                stmt = select(database.PostMedia.id).where(database.PostMedia.post_id == post_id)
                result = await session.execute(stmt)
                media_ids = [row[0] for row in result.all()]

                return {
                    "ids": media_ids
                }
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Error get media by post {post_id}: {str(e)}"
            )
        
#http://autopost.work.gd:8080/api/profile/30b84fcf-9ccc-48d4-bbe9-f1631b5a9c8e/posts/36799488-5935-421e-a748-6e41cbfda029/media
@app.post("/api/profile/{profile_id}/posts/{post_id}/media", tags=["posts"])
async def upload_media(profile_id: str, post_id: str, file_type: str, file: UploadFile = File(...),access_token: Annotated[str, Cookie()] = ""):
    """Принять медиа и вернуть его сгенерированный id"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")
    
    if file_type not in ["image", "video"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Must be 'image' or 'video'"
        )
    async with database.async_session() as session:
        try:
            async with session.begin():
                post = await session.get(database.Post, post_id)
                if not post:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Post with id {post_id} not found"
                    )
            
                file_ext = file.filename.split('.')[-1]
                file_name = f"{uuid.uuid4()}.{file_ext}"
                upload_dir = Path("uploads/media")
                upload_dir.mkdir(exist_ok=True)
                file_path = upload_dir / file_name
            
                with open(file_path, "wb") as buffer:
                    content = await file.read()
                    buffer.write(content)
            
                new_media = database.PostMedia(
                    post_id=post_id,
                    file_type=file_type,
                    file_path=str(file_path)
                )
                session.add(new_media)
                await session.flush() 
                await session.commit()
            
            return {
                "media_id": new_media.id
            }   
                
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Error upload media by post {post_id}: {str(e)}"
            )

@app.get("/api/profile/{profile_id}/posts/{post_id}/media/{media_id}", tags=["posts"])
async def get_post_media(media_id: str, profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получение конкретного медиафайла поста в формате base64"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")
    
    async with database.async_session() as session:
        try:
            async with session.begin():
                media = await session.get(database.PostMedia, media_id)
                if not media or media.post_id != post_id:
                    raise HTTPException(
                        status_code=404,
                        detail="Media file not found"
                    )

            with open(media.file_path, "rb") as file:
                content = base64.b64encode(file.read()).decode('utf-8')

            return {
                "type": media.file_type,
                "content": content
            }
        
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Error fetching media content: {str(e)}"
            )

@app.put("/api/profile/{profile_id}", tags=["profile"])
async def update_profile(profile_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Обновить профиль"""
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
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")
    try:
        keycloak_admin = KeycloakAdmin(
            server_url=settings.KEYCLOAK_URL,
            username=settings.KEYCLOAK_ADMIN,
            password=settings.KEYCLOAK_ADMIN_PASSWORD,
            realm_name="master",
            user_realm_name=settings.REALM,  
            client_id=settings.CLIENT_ADMIN_ID, 
            client_secret_key=settings.CLIENT_ADMIN_SECRET_KEY 
        )
        sessions = keycloak_admin.get_sessions(user_id)

        formatted_sessions = []
        for session in sessions:
            session_data = {
                "session_id": session.get("id"),
                "ip_address": session.get("ipAddress"),
                "client_id": list(session.get("clients", {}).values())[0] if session.get("clients") else None,
                "current": session.get("id") == token_info.get("sid")
            }

            if session.get("start"):
                utc_time = datetime.fromtimestamp(session["start"]/1000, tz=timezone.utc)
                session_data["started_at"] = utc_time.astimezone(MOSCOW_TZ).isoformat()
            if session.get("lastAccess"):
                utc_time = datetime.fromtimestamp(session["lastAccess"]/1000, tz=timezone.utc)
                session_data["last_accessed"] = utc_time.astimezone(MOSCOW_TZ).isoformat()
            if session.get("expiration"):
                utc_time = datetime.fromtimestamp(session["expiration"]/1000, tz=timezone.utc)
                session_data["expires_at"] = utc_time.astimezone(MOSCOW_TZ).isoformat()
    
            formatted_sessions.append(session_data)

        return {"sessions": formatted_sessions}
    
    except Exception as e:
        logger.error(f"Failed to get user sessions: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve sessions")

#!!!!!!!завершает сессию в клоаке, но пользователь(ip) остается авторизован(( 
@app.delete("/api/profile/{profile_id}/sessions/{session_id}", tags=["profile"])
async def terminate_session(profile_id: str, session_id: str, access_token: Annotated[str, Cookie()] = ""
):
    """Завершить конкретную сессию"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")
    
    try:
        keycloak_admin = KeycloakAdmin(
            server_url=settings.KEYCLOAK_URL,
            username=settings.KEYCLOAK_ADMIN,
            password=settings.KEYCLOAK_ADMIN_PASSWORD,
            realm_name="master",
            user_realm_name=settings.REALM,  
            client_id=settings.CLIENT_ADMIN_ID, 
            client_secret_key=settings.CLIENT_ADMIN_SECRET_KEY 
        )

        response = keycloak_admin.raw_delete(
            f"admin/realms/{settings.REALM}/sessions/{session_id}"
        )

        if response.status_code == 204:
            return {"success": True}
        raise Exception(response.text)
    
    
    except Exception as e:
        logger.error(f"Failed to revoke session: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to revoke session")


@app.post("/api/profile/{profile_id}/temp-links", tags=["profile"])
async def create_temp_link(
    profile_id: str,
    duration: int = Form(...),      
    access_token: Annotated[str, Cookie()] = ""
):
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail="Error: Access rights error")

    async with database.async_session() as session:
        try:
            async with session.begin():
                expires_at = datetime.now() + timedelta(minutes=duration)
                utc_time = expires_at.astimezone(timezone.utc)
                temp_token = str(uuid.uuid4())

                login_url = (
                    f"{settings.KEYCLOAK_URL}/realms/{settings.REALM}/protocol/openid-connect/auth?"
                    f"client_id={settings.CLIENT_ID}&"
                    f"redirect_uri={settings.REDIRECT_URL}&"
                    f"response_type=code&"
                    f"login_hint={user_id}&"
                    f"state={temp_token}"
                )

                temp_link = database.TemporaryLink(
                    user_id=user_id,
                    token=temp_token,
                    expires_at=expires_at,
                    keycloak_role=None
                )
                session.add(temp_link)
                await session.flush()

                return {
                    "success": True,
                    "link": login_url,
                    "expires_at": utc_time.astimezone(MOSCOW_TZ).isoformat(),
                    "linkId": temp_link.id
                }

        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Error creating temporary link: {str(e)}"
            )
    

@app.get("/api/profile/{profile_id}/temp-links", tags=["profile"])
async def get_temp_links(profile_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить все временные ссылки пользователя"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error Access rights error")

    async with database.async_session() as session:
        try:
            async with session.begin():
                query = select(database.TemporaryLink).where(
                (database.TemporaryLink.user_id == user_id) &
                (database.TemporaryLink.expires_at >= datetime.now())
            )
            result = await session.execute(query)
            temp_links = result.scalars().all()

            links_data = []
            for temp_link in temp_links:
                login_url = (
                    f"{settings.KEYCLOAK_URL}/realms/{settings.REALM}/protocol/openid-connect/auth?"
                    f"client_id={settings.CLIENT_ID}&"
                    f"redirect_uri={settings.REDIRECT_URL}&"
                    f"response_type=code&"
                    f"login_hint={user_id}&"
                    f"state={temp_link.token}"
                )
                utc_time = temp_link.expires_at.astimezone(timezone.utc)
                expires_at_moscow = utc_time.astimezone(MOSCOW_TZ).isoformat()
                links_data.append({
                    "link": login_url,
                    "expires_at": expires_at_moscow,
                    "linkId": temp_link.id
                })

            return {"links": links_data}

        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Error get temporary link: {str(e)}"
            )

@app.delete("/api/profile/{profile_id}/temp-links/{link_id}", tags=["profile"])
async def revoke_temp_link(profile_id: str, link_id: str = str, access_token: Annotated[str, Cookie()] = ""):
    """Отозвать временную ссылку"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error Access rights error")
    
    async with database.async_session() as session:
        try:
            keycloak_admin = KeycloakAdmin(
                server_url=settings.KEYCLOAK_URL,
                username=settings.KEYCLOAK_ADMIN,
                password=settings.KEYCLOAK_ADMIN_PASSWORD,
                realm_name="master",
                user_realm_name=settings.REALM,
                client_id=settings.CLIENT_ADMIN_ID,
                client_secret_key=settings.CLIENT_ADMIN_SECRET_KEY,
                verify=True
            )

            async with session.begin():
                link = await session.execute(
                    select(database.TemporaryLink)
                    .where(
                        (database.TemporaryLink.id == link_id) &
                        (database.TemporaryLink.user_id == user_id)
                    )
                )
                link = link.scalar_one_or_none()

                if not link:
                    return {
                        "success": False,
                        "error": "Link not found or you don't have permission"
                    }

                try:
                    sessions = keycloak_admin.get_user_sessions(user_id)

                    for session_info in sessions:
                        if session_info.get('state') == link.token:
                            keycloak_admin.revoke_user_session(
                                user_id=user_id,
                                session_id=session_info['id']
                            )
                except Exception as session_error:
                    logger.error(f"Failed to revoke sessions: {str(session_error)}")

                await session.delete(link)
                await session.commit()

                return {"success": True}
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Error revoke temporary link: {str(e)}"
            ) 

def validate_password_complexity(password: str):
    """Проверка сложности пароля"""
    if len(password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long"
        )
    if not re.search(r"[A-Z]", password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one uppercase letter"
        )
    if not re.search(r"[a-z]", password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one lowercase letter"
        )
    if not re.search(r"[0-9]", password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one digit"
        )
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one special character"
        )

@app.put("/api/profile/{profile_id}/change_password", tags=["profile"])
async def change_password(profile_id: str, new_password: str = Form(...), access_token: Annotated[str, Cookie()] = "",
                          #current_password: str = Form(...) # Текущий пароль для подтверждения
                          ): 
    """Изменить пароль пользователя"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error Access rights error")
    
    validate_password_complexity(new_password)
    try:
        keycloak_admin = KeycloakAdmin(
            server_url=settings.KEYCLOAK_URL,
            username=settings.KEYCLOAK_ADMIN,
            password=settings.KEYCLOAK_ADMIN_PASSWORD,
            realm_name="master",
            user_realm_name=settings.REALM,
            client_id=settings.CLIENT_ADMIN_ID,
            client_secret_key=settings.CLIENT_ADMIN_SECRET_KEY,
            verify=True
        )
        #try:
        #    keycloak_openid.token(
        #        username=keycloak_admin.get_user(user_id)['username'],
        #        password=current_password,
        #        grant_type="password"
        #    )
        #except Exception:
        #    raise HTTPException(
        #        status_code=400,
        #        detail="Current password is incorrect"
        #    )

        keycloak_admin.set_user_password(
            user_id=user_id,
            password=new_password,
            temporary=False
        )
        return {"success": True}

    except Exception as e:
        raise HTTPException(
                status_code=400,
                detail=f"Error change password: {str(e)}"
            )  
    
@app.post("/api/profile/{profile_id}/posts/{post_id}/hashtags/generate", tags=["posts"])
async def generate_post_hashtags(profile_id: str, post_id: str, text: str = Form(...), access_token: Annotated[str, Cookie()] = ""):
    """Сгенерировать хэштеги для поста"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail="Error: Access rights error")
    
    try:
        # Генерация хэштегов с помощью OpenAI
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://llm.api.cloud.yandex.net/foundationModels/v1/completion",
                headers={
                    "Authorization": f"Api-Key {settings.YC_API_KEY}",
                    "x-folder-id": settings.YC_FOLDER_ID
                },
                json={
                    "modelUri": f"gpt://{settings.YC_FOLDER_ID}/yandexgpt-lite",
                    "completionOptions": {
                        "stream": False,
                        "temperature": 0.3,
                        "maxTokens": "10"
                    },
                    "messages": [
                        {
                            "role": "system",
                            "text": "Сгенерируй ровно 5 хэштегов через пробел. Только хэштеги, без пояснений."
                        },
                        {
                            "role": "user", 
                            "text": text
                        }
                    ]
                },
                timeout=10.0
            )
            response.raise_for_status()
            
            result = response.json()
            hashtags = result["result"]["alternatives"][0]["message"]["text"].split()
        return {"hashtags": hashtags}
    
    except Exception as e:
        logger.error(f"Error generating hashtags: {e}")
        raise HTTPException(status_code=500, detail="Error generating hashtags")
        

@app.get("/api/profile/{profile_id}/tokens", tags=["profile"])
async def get_tokens(profile_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить токены социальных сетей"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail="Error: Access rights error")
    
    async with database.async_session() as session:
        try:
            async with session.begin():
                query = select(
                database.UserToken.service,
                database.UserToken.token_type,
                database.UserToken.token_value
                ).where(
                    database.UserToken.user_id == user_id
                )
                result = await session.execute(query)
                tokens = result.fetchall()
                print(tokens)

            if not tokens:
                raise HTTPException(
                    status_code=404,
                    detail="No tokens found for this user"
                )
            response = {
                "telegramBotToken": None,
                "telegramChatId": None,
                "vkGroupToken": None,
                "vkUserToken": None,
                "okGroupToken": None
            }

            for token in tokens:
                service = token.service
                token_type = token.token_type
                
                if service == "telegram" and token_type == "bot":
                    response["telegramBotToken"] = token.token_value
                elif service == "telegram" and token_type == "chat":
                    response["telegramChatId"] = token.token_value
                elif service == "vk" and token_type == "group":
                    response["vkGroupToken"] = token.token_value
                elif service == "vk" and token_type == "user":
                    response["vkUserToken"] = token.token_value
                elif service == "ok" and token_type == "group":
                    response["okGroupToken"] = token.token_value

            response = {k: v for k, v in response.items() if v is not None}
            return response
        
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error get tokens: {str(e)}"
            )

@app.put("/api/profile/{profile_id}/tokens", tags=["profile"])
async def update_tokens(
    profile_id: str,
    telegramBotToken: str = Form(None),
    telegramChatId: str = Form(None),
    vkGroupToken: str = Form(None),
    vkUserToken: str = Form(None),
    okGroupToken: str = Form(None),
    access_token: Annotated[str, Cookie()] = ""
):
    """Обновить токены социальных сетей"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail="Error: Access rights error")
    
    async with database.async_session() as session:
        try:
            async with session.begin():
                token_updates = {
                    ("telegram", "bot"): telegramBotToken,
                    ("telegram", "chat"): telegramChatId,
                    ("vk", "group"): vkGroupToken,
                    ("vk", "user"): vkUserToken,
                    ("ok", "group"): okGroupToken
                }

                updated_tokens = []
                for (service, token_type), token_value in token_updates.items():
                    query = select(database.UserToken).where(
                        (database.UserToken.user_id == user_id) &
                        (database.UserToken.service == service) &
                        (database.UserToken.token_type == token_type)
                    )
                    result = await session.execute(query)
                    existing_token = result.scalar_one_or_none()

                    if existing_token:
                        existing_token.token_value = token_value
                        existing_token.last_updated = datetime.now()
                        session.add(existing_token)
                    else:
                        new_token = database.UserToken(
                            user_id=user_id,
                            service=service,
                            token_type=token_type,
                            token_value=token_value,
                            last_updated=datetime.now()
                        )
                        session.add(new_token)
                
                    updated_tokens.append(f"{service}_{token_type}")

                if not updated_tokens:
                    raise HTTPException(
                        status_code=400,
                        detail="No valid tokens provided for update"
                    )

                await session.commit()
                return {"success": True}

        except Exception as e:
            logger.error(f"Error updating tokens: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail="Internal server error"
            )

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

@app.get("/health")
async def health():
    auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        
    return {"status": "ok"}

@app.get("/metrics")
async def metrics():
    auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)

    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.options("/api/{path:path}")
async def options_handler():
    return Response(headers={
        "Access-Control-Allow-Origin": "http://autopost.work.gd",
        "Access-Control-Allow-Methods": "POST, GET, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie",
        "Access-Control-Allow-Credentials": "true"
    })

#openapi_schema = app.openapi()
#with open("openapi.json", "w") as f:
#    json.dump(openapi_schema, f)