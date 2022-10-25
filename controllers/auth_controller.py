from flask import Blueprint, request
from init import db, bcrypt
from datetime import timedelta
from models.user import User, UserSchema
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import create_access_token



auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


# Routes
@auth_bp.route('/register/', methods=['POST'])
def auth_register():
    try:
        # print(request.json)
        # return 'empty'
        # user_info = UserSchema().load(request.json)

        #  Create a new user model instance from the user_info
        user = User(
            email = request.json['email'],
            password = bcrypt.generate_password_hash(request.json['password']).decode('utf_8'),
            name = request.json.get('name')
        )

        # Add and commit user to the DB
        db.session.add(user)
        db.session.commit()
        # Respond to the client
        return UserSchema(exclude=['password']).dump(user), 201
    except IntegrityError:
        return {'error': 'Email address already in use'}, 409


@auth_bp.route('/login/', methods=['POST'])
def auth_login():
    print(request.json)
    stmt = db.select(User).filter_by(email=request.json['email'])
    # print(stmt.compile().params)
    user = db.session.scalar(stmt)
    print(user)
    if user and bcrypt.generate_password_hash(user.password, request.json['password']):
        token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=1))
        return {'email': user.email, 'token': token, 'is_admin': user.is_admin}
        # return UserSchema(exclude=['password']).dump(user), 200
    else:
        return {'error': 'Invalid email or password'}, 401