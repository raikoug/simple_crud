from flask import Flask, jsonify, request
import json
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

ALLOWED_METHODS=['GET', 'POST', 'PUT', 'DELETE']


def verify_password(function):
    def auth_wrapper(*args, **kwargs):
        users = get_users()
        username = request.authorization['username']
        password_provided = request.authorization['password']
        if not username in users:
            return username_or_password_are_invalid()
        
        if  not check_password_hash(users[username]['password'], password_provided):
            return username_or_password_are_invalid()
        
        request.user = users[username]
        return function(*args, **kwargs)
    
    return auth_wrapper


# Path: /
@app.route('/', methods=["GET"])
@verify_password
def get():
    print(request.authorization)
    print(request.user)
    return jsonify(get_users())

@app.route('/', methods=["POST"])
def post():
    return jsonify(get_users())



def get_users():
    return json.loads(open('users.json').read())


def not_authorized():
    return jsonify({'error': 'Not Authorized'}), 403

def username_or_password_are_invalid():
    return jsonify({'error': 'Username or password are invalid'}), 400