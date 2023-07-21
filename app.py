from flask import Flask, jsonify, request, Response
import json
from werkzeug.security import generate_password_hash, check_password_hash

class col:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

c = col()

class User: 
    username = ""
    password = ""
    role = ""
    email = ""
    firstName = ""
    lastName = ""
    unit = ""
    def __init__(self, username, password, role, email, firstName, lastName, unit):
        self.username = username
        self.password = password
        self.role = role
        self.email = email
        self.firstName = firstName
        self.lastName = lastName
        self.unit = unit
    
    def print(self):
        print(f"Username: {self.username}")
        print(f"Password: {self.password}")
        print(f"Role: {self.role}")
        print(f"Email: {self.email}")
        print(f"First Name: {self.firstName}")
        print(f"Last Name: {self.lastName}")
        print(f"Unit: {self.unit}")

    def __repr__(self) -> str:
        return f"{self.email}: {self.username} {self.password} {self.role} {self.email} {self.firstName} {self.lastName} {self.unit}"
    
    def __txt__(self) -> str:
        return f"{self.email}: {self.username} {self.password} {self.role} {self.email} {self.firstName} {self.lastName} {self.unit}"


try:
    from icecream import ic
except ImportError:  # Graceful fallback if IceCream isn't installed.
    ic = lambda *a: None if not a else (a[0] if len(a) == 1 else a)  # noqa

app = Flask(__name__)

ALLOWED_METHODS=['GET', 'POST', 'PUT', 'DELETE']
NOT_ALLOWED_METHODS=['OPTIONS', 'PATCH', 'HEAD']


def verify_password(function):
    def my_auth_wrapper(*args, **kwargs):
        users = get_users()
        try:
            username = request.authorization['username']
            password_provided = request.authorization['password']
        except:
            return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )
        if not username in users:
            return username_or_password_are_invalid()
        
        if  not check_password_hash(users[username]['password'], password_provided):
            return username_or_password_are_invalid()
        
        request.user = users[username]
        return function(*args, **kwargs)

    return my_auth_wrapper


# Path: /
@app.route('/', methods=NOT_ALLOWED_METHODS, endpoint='default')
def default():
    #method not implemented
    return method_not_allowed()

@app.errorhandler(404)
def page_not_found(e):
    return resource_not_found()

@app.route('/about', methods=["GET"], endpoint='about')
def about():
    return resource_not_found()


@app.route('/', methods=["GET"], endpoint='get')
@verify_password
def get():

    user = get_user_as_class(request.user)
    if user.role == "admin":
        print(f"{c.OKGREEN}Serving Users{c.ENDC}")
        return jsonify(get_users())

    if user.role == "manager":
        users = get_users_as_class()
        unit_users = get_user_under_manager(user.unit, users)
        ic(unit_users)
        print(f"{c.OKGREEN}Serving Users in {user.unit}{c.ENDC}")
        return jsonify(users_class_to_dict(unit_users))
    
    print(f"{c.FAIL}User {user.email} is not authorized to get users{c.ENDC}")
    return not_authorized()    

@app.route('/', methods=["POST"], endpoint='post')
@verify_password
def post():
    requesting_user = get_user_as_class(request.user)
    if requesting_user.role == "user":
        print(f"{c.FAIL}User {requesting_user.email} is not authorized to add users{c.ENDC}")
        return forbidden_resource()
    
    data = request.get_json(silent=True)
    if not data:
        print(f"{c.FAIL}No data has been provided in the body or data is not a valid json{c.ENDC}")
        return no_data_provided_or_not_json()
    
    try:
        # cast data to user class
        users_to_add = users_dict_as_class(data)
    except:
        print(f"{c.FAIL}Body is not valid users{c.ENDC}")
        return body_is_not_valid_users()
    
    return add_users(users_to_add, requesting_user)

@app.route('/', methods=["PUT"], endpoint='put')
@verify_password
def put():
    requesting_user = get_user_as_class(request.user)
    if requesting_user.role == "user":
        print(f"{c.FAIL}User {requesting_user.email} is not authorized to edit users{c.ENDC}")
        return forbidden_resource()
    
    data = request.get_json(silent=True)
    if not data:
        return no_data_provided_or_not_json()
    
    try:
        # cast data to user class
        user_to_edit = get_put_user_as_class(data)
    except:
        return body_is_not_valid_users()
    
    return edit_user(user_to_edit, requesting_user)

@app.route('/', methods=["DELETE"], endpoint='delete')
@verify_password
def delete():
    requesting_user = get_user_as_class(request.user)
    if requesting_user.role == "user":
        print(f"{c.FAIL}User {requesting_user.email} is not authorized to delete users{c.ENDC}")
        return forbidden_resource()
    
    data = request.get_json(silent=True)
    if not data:
        print(f"{c.FAIL}No data has been provided in the body or data is not a valid json{c.ENDC}")
        return no_data_provided_or_not_json()
    
    # dat\a is just this json:
    # {
    #     "email": "email"
    # }
    # check if data is correct:
    if not 'email' in data:
        print(f"{c.FAIL}Body is not valid users{c.ENDC}")
        return body_is_not_valid_users()

    email_to_delete = data['email']
    
    
    return delete_user(email_to_delete, requesting_user)



def edit_user(user_to_edit: User, requesting_user: User):
    users_in_db = json.loads(open('users.json').read())
    if not user_to_edit.email in users_in_db:
        print(f"{c.FAIL}User {user_to_edit.email} does not exist{c.ENDC}")
        return jsonify({'error': 'User does not exist'}), 400
    
    if requesting_user.role != "admin":
        if requesting_user.unit != user_to_edit.unit:
            print(f"{c.FAIL}User is not in the same unit as the requesting user{c.ENDC}")
            return jsonify({'error': 'User is not in the same unit as the requesting user'}), 403
        elif user_to_edit.role != "user":
            print(f"{c.FAIL}User with role {user_to_edit.role} cannot be edited by a manager{c.ENDC}")
            return jsonify({'error': 'User with role {user.role} cannot be edited by a manager'}), 403

    users_in_db[user_to_edit.email] = user_class_to_dict(user_to_edit)
    if not user_to_edit.password.startswith('pbkdf2'):
        users_in_db[user_to_edit.email]['password'] = generate_password_hash(user_to_edit.password)

    open('users.json', 'w').write(json.dumps(users_in_db, indent=2))
    return jsonify({'success': 'User edited'}), 200

def delete_user(email_to_delete: str, requesting_user: User):
    users_in_db = json.loads(open('users.json').read())
    if not email_to_delete in users_in_db:
        print(f"{c.FAIL}User {email_to_delete} does not exist{c.ENDC}")
        return jsonify({'error': 'User does not exist'}), 400
    
    if requesting_user.role != "admin":
        if requesting_user.unit != users_in_db[email_to_delete]['unit']:
            print(f"{c.FAIL}User is not in the same unit as the requesting user{c.ENDC}")
            return jsonify({'error': 'User is not in the same unit as the requesting user'}), 403
        elif users_in_db[email_to_delete]['role'] != "user":
            print(f"{c.FAIL}User with role {users_in_db[email_to_delete]['role']} cannot be deleted by a manager{c.ENDC}")
            return jsonify({'error': 'User with role {user.role} cannot be deleted by a manager'}), 403

    del users_in_db[email_to_delete]
    print(f"{c.OKGREEN}User {email_to_delete} deleted{c.ENDC}")
    open('users.json', 'w').write(json.dumps(users_in_db, indent=2))
    return jsonify({'success': 'User deleted'}), 200

def add_users(users_to_add: dict, requesting_user: User):
    result = {"added": [], "errors": []}
    users_in_db = json.loads(open('users.json').read())
    for email, user in users_to_add.items():
        if email in users_in_db:
            result['errors'].append(f"User {email} already exists")
            print(f"{c.FAIL}User {email} already exists{c.ENDC}")
            continue
        if requesting_user.role != "admin":
            if requesting_user.unit != user.unit:
                result['errors'].append(f"User {email} is not in the same unit as the requesting user")
                print(f"{c.FAIL}User {email} is not in the same unit as the requesting user{c.ENDC}")
                continue
            elif user.role != "user":
                result['errors'].append(f"User {email} with role {user.role} cannot be added by a manager")
                print(f"{c.FAIL}User {email} with role {user.role} cannot be added by a manager{c.ENDC}")
                continue

        users_in_db[email] = user_class_to_dict(user)
        users_in_db[email]['password'] = generate_password_hash(users_in_db[email]['password'])

        result['added'].append(f"User {email} added")
        print(f"{c.OKGREEN}User {email} added{c.ENDC}")

    open('users.json', 'w').write(json.dumps(users_in_db, indent=2))
    if result['errors']:
        return jsonify(result), 207
    else:
        return jsonify(result), 200

def get_user_under_manager(unit: str, users_class: list) -> list:
    users_under_manager = []
    for email, user in users_class.items():
        ic(user)
        if user.unit == unit and user.role == "user":
            users_under_manager.append(user)
    return users_under_manager

def user_class_to_dict(user: User):
    return {
        'username': user.username,
        'password': user.password,
        'role': user.role,
        'email': user.email,
        'firstName': user.firstName,
        'lastName': user.lastName,
        'unit': user.unit
    }

def users_class_to_dict(users: dict):
    users_dict = {}
    for user in users:
        users_dict[user.email] = {
            'username': user.username,
            'password': user.password,
            'role': user.role,
            'email': user.email,
            'firstName': user.firstName,
            'lastName': user.lastName,
            'unit': user.unit
        }
    return users_dict

def get_users():
    return json.loads(open('users.json').read())

def users_dict_as_class(users: dict) -> dict:
    users_class = {}
    for email, user in users.items():
        users_class[email] = User(user['username'], user['password'], user['role'], user['email'], user['firstName'], user['lastName'], user['unit'])
    
    return users_class

def get_users_as_class():
    users = get_users()
    users_class = {}
    for user in users:
        users_class[user] = User(user, users[user]['password'], users[user]['role'], users[user]['email'], users[user]['firstName'], users[user]['lastName'], users[user]['unit'])
    return users_class

def get_user_as_class(user: dict):
    return User(user['username'], user['password'], user['role'], user['email'], user['firstName'], user['lastName'], user['unit'])

def get_put_user_as_class(user_putted: dict):
    k,user = user_putted.popitem()
    return User(user['username'], user['password'], user['role'], user['email'], user['firstName'], user['lastName'], user['unit'])



def not_authorized():
    return jsonify({'error': 'Not Authorized'}), 403

def username_or_password_are_invalid():
    return jsonify({'error': 'Username or password are invalid'}), 400

def no_data_provided_or_not_json():
    return jsonify({'error': 'No data has been provided in the body or data is not a valid json'}), 400

def body_is_not_valid_users():
    return jsonify({'error': 'Body is not valid users'}), 400

def forbidden_resource():
    return jsonify({'error': 'Forbidden resource'}), 403

def method_not_allowed():
    return jsonify({'error': 'Method not implemented for the resource'}), 405

def resource_not_found():
    return jsonify({'error': 'The resource cannot be found'}), 404