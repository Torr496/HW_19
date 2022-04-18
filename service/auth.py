import base64
from flask import request, abort
import calendar
import datetime
import hashlib
import hmac
import jwt

from constans import PWD_HASH_SALT, PWD_HASH_ITERATIONS, JWT_SECRET, JWT_ALGORITHM
from implemented import user_service


def auth_check():
    if "Authorization" not in request.headers:
        return False
    token = request.headers["Authorization"].split("Bearer ")[-1]
    return jwt_decode(token)


def jwt_decode(token):
    try:
        decoded_jwt = jwt.decode(token, JWT_SECRET, JWT_ALGORITHM)
    except:
        return False
    else:
        return decoded_jwt


def auth_required(func):
    def wrapper(*args, **kwargs):
        if auth_check():
            return func(*args, **kwargs)
        abort(401, "Authorization Error")
    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        decoded_jwt = auth_check()
        if decoded_jwt:
            role = decoded_jwt.get("role")
            if role == "admin":
                return func(*args, **kwargs)
        abort(401, "Admin role required")
    return wrapper

def generate_token(data):
    min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    data["exp"] = calendar.timegm(min30.timetuple())
    access_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)
    days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
    data["exp"] = calendar.timegm(days130.timetuple())
    refresh_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {'access_token': access_token, 'refresh_token': refresh_token}


def compare_passwords(password_hash, other_password) -> bool:
    return hmac.compare_digest(
        base64.b64decode(password_hash),
        hashlib.pbkdf2_hmac('sha256', other_password.encode(), PWD_HASH_SALT, PWD_HASH_ITERATIONS)
    )


def login_user(req_json):
    user_name = req_json.get("username")
    user_pass = req_json.get("password")
    if user_name and user_pass:
        user = user_service.get_filter({"username": user_name})
        if user:
            pass_hashed =user[0].password
            print(pass_hashed)
            req_json["role"] =user[0].role
            if compare_passwords(pass_hashed, other_password=user_pass):
                return generate_token(req_json)
    return False

def refresh_user_token(req_json):
    refresh_token = req_json.get("refresh_token")
    data = jwt_decode(refresh_token)
    if data:
        tokens = generate_token(data)
        return tokens
    return False


# def admin_required(func):
#     def wrapper(*args, **kwargs):
#         if 'Authorization' not in request.headers:
#             abort(401)
#
#         data = request.headers['Authorization']
#         token = data.split("Bearer ")[-1]
#         try:
#             user = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
#             role = user.get("role")
#             if role != "admin":
#                 abort(400)
#         except Exception as e:
#             print("JWT Decode Exception", e)
#             abort(401)
#         return func(*args, **kwargs)
#
#     return wrapper