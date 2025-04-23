import base64
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
from sqlalchemy import text, select, join

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


@app.get("/api/profile", tags=["profile"])
async def profile_page(access_token: Annotated[str, Cookie()] = ""):
    """Возвращает id профиля(если не аутентифицирован -> на страницу аутентификации) """
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
                    name = token_info.get('name') #полное имя (first + last name)

                    new_user = database.User(
                        id=profile_id,
                        username=username,
                        name=name,
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
    """Получить пост пользователя"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error Access rights error")

    async with database.async_session() as session:
        try:
            async with session.begin():
                result = await session.execute(
                    text("SELECT * FROM posts WHERE id = :user_id"),
                    {"user_id": user_id}
                )
                posts_data = result.mappings().fetchone() 
                if not posts_data:
                    return {"message": "User not exists", "user_id": -1}
                user_post = dict(posts_data)
                return {"message": "User exists", "user_id": user_post.id}
        except Exception as e:
            await session.rollback()
            raise HTTPException(status_code=400, detail=str(e)) 
        

@app.post("/api/profile/{profile_id}/posts/", tags=["posts"])
async def create_post(
        profile_id: str,
        access_token: Annotated[str, Cookie()] = ""
):
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
                        created_at=datetime.now()
                )
                session.add(new_post)
                await session.commit()
                await session.refresh(new_post)  # Обновляем объект, чтобы получить ID
                return {"message": "New post", "post_id": new_post.id}
            
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Error creating post: {str(e)}"
            )


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
async def get_text(profile_id: str, post_id: str, text_data: dict, access_token: Annotated[str, Cookie()] = ""):
    """Обновить существующий пост"""
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
                detail=f"Error get text by post {post_id}: {str(e)}"
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

                await session.refresh(post, ["hashtags"])
                hashtags = [hashtag.hashtag for hashtag in post.hashtags]

                return {
                    "hashtags": hashtags
                }    
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Error get hashtags by post {post_id}: {str(e)}"
            )
        
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
        

@app.post("/api/profile/{profile_id}/posts/{post_id}/media", tags=["posts"])
async def get_id_media(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
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
                
                
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Error post media by post {post_id}: {str(e)}"
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

        # Читаем файл и конвертируем в base64
            with open(media.file_path, "rb") as file:
                content = base64.b64encode(file.read()).decode('utf-8')

            return {
                "type": media.file_type,
                "content": content
            }
        except FileNotFoundError:
            raise HTTPException(
                status_code=404,
                detail="Media file not found on server"
            )
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Error fetching media content: {str(e)}"
            )



@app.get("/api/profile/{profile_id}", tags=["profile"])
async def get_profile_data(profile_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить данные конкретного профиля"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error Access rights error")

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
                "email": user_info.email,
                "name": user_info.name
            }
        ],
        "user_sessions": [
            {
                "id": session.id, #id сессии 
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
            server_url=settings.KEYCLOAK_URL,
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
                "sid": session.get("id"),
                "user_id": session.get("userId"),
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
    
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error Access rights error")
    
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
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error Access rights error")
    
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
 

@app.get("/api/profile/{profile_id}/posts/{post_id}", tags=["posts"])
async def get_post(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Получить конкретный пост"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error Access rights error")

    async with database.async_session() as session:
        try:
            async with session.begin():
                query = (
                    select(
                database.posts.c.text,
                database.posts.c.created_at,
                database.post_media.c.id.label("media_id"),
                database.post_media.c.file_type,
                database.post_media.c.file_path
            )
            .select_from(
                join(database.posts, database.post_media, database.posts.c.id == database.post_media.c.post_id)
            )
            .where(
                (database.posts.c.id == post_id) & 
                (database.posts.c.user_id == profile_id) 
            )
            )
        
            result = await session.execute(query)
            post_data = result.fetchall()
        
            if not post_data:
                raise HTTPException(status_code=404, detail="Post not found")

        except Exception as e:
            await session.rollback()
            raise HTTPException(status_code=400, detail=str(e))
        
        response = {
            "post_info": {
                "text": post_data[0].text,
                "created_at": post_data[0].created_at.isoformat(),
                "media": [
                    {
                        "id": item.media_id,
                        "file_type": item.file_type,
                        "file_path": item.file_path
                    } for item in post_data
                ]
            }
        }
        
        return response


@app.delete("/api/profile/{profile_id}/posts/{post_id}", tags=["posts"])
async def delete_post(profile_id: str, post_id: str, access_token: Annotated[str, Cookie()] = ""):
    """Удалить пост"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    user_id = token_info.get('sub')

    if profile_id != user_id:
        raise HTTPException(status_code=403, detail=f"Error: Access rights error")
    
    async with database.async_session() as session:
        #try:
        #    async with session.begin():
                
            
        #except Exception as e:
        #    await session.rollback()
        #    raise HTTPException(
        #        status_code=400,
        #        detail=f"Error get text by post {post_id}: {str(e)}"
        #    )

@app.post("/api/profile/{profile_id}/posts/{post_id}/hashtags/generate", tags=["posts"])
async def generate_post_hashtags(profile_id: str, post_id: str, text: str = Form(...), access_token: Annotated[str, Cookie()] = ""):
    """Сгенерировать хэштеги для поста"""
    if not access_token or not (token_info := decode_token(access_token)):
        auth_url = keycloak_openid.auth_url(redirect_uri=settings.REDIRECT_URL)
        return RedirectResponse(auth_url)
    pass

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