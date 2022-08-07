from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS, ALGO, SECRET
from flask import abort
from dao.auth import AuthDAO
from dao.model.user import User
import hashlib
import datetime
import calendar
import jwt


class AuthService:

    def __init__(self, dao: AuthDAO):
        self.dao = dao

    def get_hash(self, password):
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ).decode("utf-8", "ignore")


    def generate_tokens(self, user_data):
        # access_token на 30 минут.
        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        user_data['exp'] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(user_data, SECRET, algorithm=ALGO)

        # refresh_token на 130 дней.
        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        user_data['exp'] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(user_data, SECRET, algorithm=ALGO)

        return {"access_token": access_token, "refresh_token": refresh_token}


    def check_user(self, data):
        username = data.get("username", None)
        password = data.get("password", None)

        if None in [username, password]:
            abort(400)

        user: User = self.dao.get_user_by_username(username)

        if user is None:
            return {"error": "Неверные учётные данные"}, 401

        password_hash = self.get_hash(password)

        if password_hash != user.password:
            return {"error": "Неверные учётные данные"}, 401

        user_data = {
            "username": user.username,
            "role": user.role
        }
        return user_data


    def refresh_token(self, token):
        refresh_token = token.get("refresh_token", None)

        if refresh_token is None:
            abort(400)

        try:
            data = jwt.decode(refresh_token, SECRET, algorithms=[ALGO])
        except Exception as e:
            abort(401)

        username = data.get("username")
        user: User = self.dao.get_user_by_username(username)

        user_data = {
            "username": user.username,
            "role": user.role
        }

        return user_data