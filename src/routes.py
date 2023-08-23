# routes.py
from flask import request, Response, jsonify
from flask import current_app as app
from utils import get_full_user, get_resumed_user, generate_token, create_user, get_users, use_get_user, put_user, patch_user, delete_user

@app.route('/login', methods=['POST'])
def login():
    return generate_token()

@app.route('/users', methods=['POST'])
def users_create():
    return create_user()

@app.route('/users', methods=['GET'])
def users_list():
    return get_users()

@app.route('/users/<user_id>', methods=['GET'])
def users_get(user_id):
    return use_get_user(user_id)

@app.route('/users/<user_id>', methods=['PUT'])
def users_update(user_id):
    return put_user(user_id)

@app.route('/users/<user_id>', methods=['PATCH'])
def users_patch(user_id):
    return patch_user(user_id)

@app.route('/users/<user_id>', methods=['DELETE'])
def users_delete(user_id):
    return delete_user(user_id)
