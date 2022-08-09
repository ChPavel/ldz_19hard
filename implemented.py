import jwt
from flask import request, abort
from constants import SECRET, ALGO
from dao.director import DirectorDAO
from dao.genre import GenreDAO
from dao.movie import MovieDAO
from dao.user import UserDAO
from dao.auth import AuthDAO
from service.director import DirectorService
from service.genre import GenreService
from service.movie import MovieService
from service.user import UserService
from service.auth import AuthService
from setup_db import db

director_dao = DirectorDAO(session=db.session)
genre_dao = GenreDAO(session=db.session)
movie_dao = MovieDAO(session=db.session)
user_dao = UserDAO(session=db.session)
auth_dao = AuthDAO(session=db.session)

director_service = DirectorService(dao=director_dao)
genre_service = GenreService(dao=genre_dao)
movie_service = MovieService(dao=movie_dao)
user_service = UserService(dao=user_dao)
auth_service = AuthService(dao=auth_dao)


def auth_required(func):
    def wrepper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)
        return func(*args, **kwargs)
    return wrepper


def admin_required(func):
    def wrepper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split('Bearer ')[-1]
        try:
            user = jwt.decode(token, SECRET, algorithms=[ALGO])
            role_user = user.get("role")
        except Exception as e:
            print(f'JWT Decode Exseption: {e}')
            abort(401)
        if role_user != 'admin':
            abort(403)
        return func(*args, **kwargs)
    return wrepper

