# utils.py
import requests
from flask import request, Response, jsonify, current_app as app
import re
from collections import OrderedDict

# URLs to be used inside docker
DOCKER_SERVER_URL = 'https://keycloak:8080/auth'
DOCKER_TOKEN_URL = 'http://keycloak:8080/auth/realms/Construc-sw-2023-1/protocol/openid-connect/token'
DOCKER_USERS_URL = 'http://keycloak:8080/auth/admin/realms/Construc-sw-2023-1/users/'

def get_full_user(user_id):
    # Requesting the user info
    token = request.headers.get('Authorization')

    request_url = DOCKER_USERS_URL + user_id
    headers = {'Authorization': token}
    response = requests.get(request_url, headers=headers)

    # Exception handling
    if response.status_code == 400:
        return jsonify({'error_code': 'OA-400','error_description': 'Bad Request: Request structure error'}), 400
    if response.status_code == 401:
        return jsonify({'error_code': 'OA-401','error_description': 'Unauthorized: Invalid Token or username/password'}), 401
    if response.status_code == 403:
        return jsonify({'error_code': 'OA-403','error_description': 'Forbidden: Missing the necessary roles or privilages'}), 403
    if response.status_code == 404:
        return jsonify({'error_code': 'OA-404','error_description': 'Not Found: User not Found'}), 404
    return jsonify(response.json()), 200

def get_resumed_user(user_id):
    # Requesting the user info
    token = request.headers.get('Authorization')

    request_url = DOCKER_USERS_URL + user_id
    headers = {'Authorization': token}
    response = requests.get(request_url, headers=headers)

    # Getting the user fields to be returned as a resumed user
    user_id = response.json()['id']
    username = response.json()['username']
    first_name = response.json()['firstName']
    last_name = response.json()['lastName']
    email = response.json()['email']
    enabled = response.json()['enabled']

    # Formating the user as an ordered dict to return the info in a easy to read format 
    user = OrderedDict(
        id=user_id,
        username=username,
        first_name=first_name,
        last_name=last_name,
        email=email,
        enabled=enabled
    )

    # Exception handling
    if response.status_code == 400:
        return jsonify({'error_code': 'OA-400','error_description': 'Bad Request: Request structure error'}), 400
    if response.status_code == 401:
        return jsonify({'error_code': 'OA-401','error_description': 'Unauthorized: Invalid Token or username/password'}), 401
    if response.status_code == 403:
        return jsonify({'error_code': 'OA-403','error_description': 'Forbidden: Missing the necessary roles or privilages'}), 403
    if response.status_code == 404:
        return jsonify({'error_code': 'OA-404','error_description': 'Not Found: User not Found'}), 404
    return Response(json.dumps(user), status=200, mimetype='application/json')

def generate_token():
    url = DOCKER_TOKEN_URL

    # Formating the payload to be sent on the correct format and sending the request
    payload = request.form.to_dict()
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(url, headers=headers, data=payload)

    # Exception handling
    if response.status_code == 400:
        return jsonify({'error_code': 'OA-404','error_description': 'Bad Request: Request Structure error'}), 400
    if response.status_code == 401:
        return jsonify({'error_code': 'OA-401','error_description': 'Unauthorized: Invalid username or password'}), 401
    return jsonify(response.json()), 200
def create_user():
    new_user = {}
    
    # Getting the token from the request header
    token = request.headers.get('Authorization')
    request_url = DOCKER_USERS_URL
    headers = {'Content-Type': 'application/json', 'Authorization': token}

    # Formating the payload and retrieving the email to be used in the exception handling
    payload = request.get_json()
    email = payload.get('email')

    # Exception handling
    if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'error_code': 'OA-400','error_description': 'Bad Request: Missing email or badly formated email'}), 400
    response = requests.post(request_url, headers=headers, json=payload)
    if response.status_code == 409:
        return jsonify({'error_code':'OA-409','error_description' : 'Conflict: This username or email already exists'}), 409
    
    # Returning the new user info as a json object
    if response.status_code == 201:
        user_info = response.headers
        new_user = {
            'location': user_info['location'].split('/')[-1]
        }
    return get_resumed_user(new_user['location']), 201

def get_users():
    token = request.headers.get('Authorization')
    url = DOCKER_USERS_URL

    headers = {'Authorization': token}
    response = requests.get(url, headers=headers)
    return jsonify(response.json()), 200

def use_get_user(user_id):
    return get_resumed_user(user_id)

def put_user(user_id):
    # Request
    token = request.headers.get('Authorization')
    url = DOCKER_USERS_URL + user_id

    headers = {'Content-Type': 'application/json', 'Authorization': token}
    
    # Formating the payload sent to our api to be sent to the keycloak server on the correct format
    payload = request.get_json()
    response = requests.put(url, headers=headers, json=payload)

    # Exception handling
    if response.status_code == 400:
        return jsonify({'error_code': 'OA-404','error_description': 'Bad Request: Request structure error'}), 400
    if response.status_code == 401:
        return jsonify({'error_code': 'OA-401','error_description': 'Unauthorized: Invalid Token or username/password'}), 401
    if response.status_code == 403:
        return jsonify({'error_code': 'OA-403','error_description': 'Forbidden: Missing the necessary roles or privilages'}), 403
    if response.status_code == 404:
        return jsonify({'error_code': 'OA-404','error_description': 'Not Found: User not Found'}), 404
    return get_resumed_user(user_id), 200

def patch_user(user_id):
    # Request
    token = request.headers.get('Authorization')
    url = DOCKER_USERS_URL + user_id

    # Formating the payload sent to our api to be sent to the keycloak server on the correct format
    headers = {'Content-Type': 'application/json','Authorization': token}
    payload = request.get_json()
    response = requests.patch(url, headers=headers, json=payload)
    
    # Exception handling
    if response.status_code == 400:
        return jsonify({'error_code': 'OA-404','error_description': 'Bad Request: Request structure error'}), 400
    if response.status_code == 401:
        return jsonify({'error_code': 'OA-401','error_description': 'Unauthorized: Invalid Token or username/password'}), 401
    if response.status_code == 403:
        return jsonify({'error_code': 'OA-403','error_description': 'Forbidden: Missing the necessary roles or privilages'}), 403
    if response.status_code == 404:
        return jsonify({'error_code': 'OA-404','error_description': 'Not Found: User not Found'}), 404
    return get_resumed_user(user_id), 200

def delete_user(user_id):
    # Request
    token = request.headers.get('Authorization')
    url = DOCKER_USERS_URL + user_id

    headers = {'Authorization': token}
    response = requests.delete(url, headers=headers)

    # Exception handling
    if response.status_code == 400:
        return jsonify({'error_code': 'OA-404','error_description': 'Bad Request: Request structure error'}), 400
    if response.status_code == 401:
        return jsonify({'error_code': 'OA-401','error_description': 'Unauthorized: Invalid Token or username/password'}), 401
    if response.status_code == 403:
        return jsonify({'error_code': 'OA-403','error_description': 'Forbidden: Missing the necessary roles or privilages'}), 403
    if response.status_code == 404:
        return jsonify({'error_code': 'OA-404','error_description': 'Not Found: User not Found'}), 404
    return jsonify({'success': True}), 200
