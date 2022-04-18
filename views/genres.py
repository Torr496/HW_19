from flask import request
from flask_restx import Resource, Namespace

from dao.model.genre import GenreSchema
from implemented import genre_service
from service.auth import auth_required, admin_required

genre_ns = Namespace('genres')
genre_schema = GenreSchema()
genres_schema = GenreSchema(many=True)

@genre_ns.route('/')
class GenresView(Resource):
    @auth_required
    def get(self):
        all_genres = genre_service.get_all()
        return genres_schema.dump(all_genres), 200

    @admin_required
    def post(self):
        req_json = request.json
        new_genre = genre_service.create(req_json)
        return f"Created id {new_genre.id}", 201


@genre_ns.route('/<int:uid>')
class GenreView(Resource):
    @auth_required
    def get(self, uid):
        genre = genre_service.get_one(uid)
        if genre:
            return genre_schema.dump(genre), 200
        return "", 404

    @admin_required
    def put(self, uid: int):
        req_json = request.json
        if not req_json.get('id'):
            req_json['id'] =uid
        if genre_service.update(req_json):
            return f"Updated id^ {uid}", 201

    @admin_required
    def delete(self, uid: int):
        if genre_service.get_one(uid):
            genre_service.delete(uid)
            return "", 204
        return "not found", 404


