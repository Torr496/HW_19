
from flask import request
from flask_restx import Resource, Namespace, reqparse

from dao.model.user import UserSchema
from implemented import user_service
from service.user import get_hash

user_ns = Namespace('users')
user_schema = UserSchema()
users_schema = UserSchema(many=True)
parser = reqparse.RequestParser()
parser.add_argument('username', type=str)
parser.add_argument('role', type=str)


@user_ns.route('/')
class UsersView(Resource):
    @user_ns.expect(parser)
    def get(self):
        req_args = parser.parse_args()
        if any(req_args.value()):
            all_users = user_service.get_filter(req_args)
        else:
            all_users = user_service.get_all()
        if all_users:
            return users_schema.dump(all_users), 200
        return "not found", 404


    def post(self):
        req_json = request.json
        password = req_json.get("password")
        password = get_hash(password)
        req_json["password"] = password
        new_user = user_service.create(req_json)
        return f"Created id: {new_user.id} Это новый пользователь", 201


@user_ns.route('/<int:bid>')
class UserView(Resource):
    def get(self, uid: int):
        user = user_service.get_one(uid)
        if user:
            return user_schema.dump(user), 200
        return "", 404

    def put(self, uid: int):
        req_json = request.json
        if not req_json.get('id'):
            req_json["id"] = uid
        if user_service.update(req_json):
            return f"Update in {uid}", 201
        return "not found", 404

    def delete(self, uid: int):
        if user_service.get_one(uid):
            user_service.delete(uid)
            return "", 204
        return "not found", 404

