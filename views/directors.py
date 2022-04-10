from flask import request
from flask_restx import Resource, Namespace

from dao.model.director import DirectorSchema
from implemented import director_service
from service.auth import auth_required, admin_required


director_ns = Namespace('directors')
director_schema = DirectorSchema
directors_schema = DirectorSchema(many=True)

@director_ns.route('/')
class DirectorsView(Resource):
    @auth_required
    def get(self):
        all_directors = director_service.get_all()
        return directors_schema.dump(all_directors), 200

    @admin_required
    def post(self):
        req_json = request.json
        new_director = director_service.create(req_json)
        return f"Created id {new_director.id}", 201


@director_ns.route('/<int:did>')
class DirectorView(Resource):
    @auth_required
    def get(self, did):
        director = director_service.get_one(did)
        if director:
            return director_schema.dump(director), 200
        return "", 404

    @admin_required
    def put(self, did: int):
        req_json = request.json
        if not req_json.get('id'):
            req_json['id'] =did
        if director_service.update(req_json):
            return f"Updated id^ {did}", 201

    @admin_required
    def delete(self, did: int):
        if director_service.delete(did):
            return "", 204
        return "not found", 404