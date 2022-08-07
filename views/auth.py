import json
from flask import request
from flask_restx import Resource, Namespace

from implemented import auth_service

auth_ns = Namespace('auth')

@auth_ns.route('/')
class UserAuthView(Resource):
    def post(self):
        req_json = request.json
        user_data = auth_service.check_user(req_json)
        if "username" and "role" not in user_data:
            return user_data
        else:
            tokens = json.dumps(auth_service.generate_tokens(user_data))
            return tokens, 201

    def put(self):
        req_json = request.json
        user_data = auth_service.refresh_token(req_json)
        if "username" and "role" not in user_data:
            return user_data
        else:
            tokens = json.dumps(auth_service.generate_tokens(user_data))
            return tokens, 201