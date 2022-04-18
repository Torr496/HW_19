from flask import request
from flask_restx import Resource, Namespace, reqparse

from dao.model.movie import MovieSchema
from implemented import movie_service
from service.auth import auth_required, admin_required

movie_ns = Namespace('movies')

movie_schema = MovieSchema()
movies_schema = MovieSchema(many=True)
parser = reqparse.RequestParser()
parser.add_argument('username', type=str)
parser.add_argument('role', type=str)


@movie_ns.route('/')
class MoviesView(Resource):
    @movie_ns.expect(parser)
    @auth_required
    def get(self):
        req_args = parser.parse_args()
        if any(req_args.values()):
            all_movies = movie_service.get_all(req_args)
        else:
            all_movies = movie_service.get_all()
        if all_movies:
            return movies_schema.dump(all_movies), 200
        return "not found", 404

    @admin_required
    def post(self):
        req_json = request.json
        new_movie = movie_service.create(req_json)
        return f"Created id: {new_movie.id}", 201


@movie_ns.route('/<int:uid>')
class MovieView(Resource):
    @auth_required
    def get(self, uid):
        movie = movie_service.get_one(uid)
        if movie:
            return movie_schema.dump(movie), 200
        return "", 404

    @admin_required
    def put(self, uid: int):
        req_json = request.json
        if not req_json.get('id'):
            req_json['id'] = uid
        if movie_service.update(req_json):
            return f"Updated id^ {uid}", 201

    @admin_required
    def delete(self, uid: int):
        if movie_service.get_one(uid):
            movie_service.delete(uid)
            return "", 204
        return "not found", 404

