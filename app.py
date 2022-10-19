from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from datetime import date, timedelta
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

app = Flask(__name__)

app.config['JSON_SORT_KEYS'] = False
app.config['JWT_SECRET_KEY'] = 'hello there'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://trello_dev:password123@127.0.0.1:5432/trello'

db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'email', 'password', 'is_admin')

class Card(db.Model):
    __tablename__ = 'cards'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    date = db.Column(db.Date)
    status = db.Column(db.String)
    priority = db.Column(db.String)

class CardSchema(ma.Schema):
    class Meta:
        fields = ('id', 'title', 'description', 'status', 'priority', 'date')
        ordered = True

# Define a custom CLI (terminal) command
@app.cli.command('create')
def create_db():
    db.create_all()
    print("Tables created")

@app.cli.command('drop')
def drop_db():
    db.drop_all()
    print("Tables dropped")

@app.cli.command('seed')
def seed_db():
    users = [
        User(
            email = 'admin@spam.com',
            password= bcrypt.generate_password_hash('eggs').decode('utf-8'),
            is_admin = True
        ),
        User(
            name = 'Chevy Chase',
            email = 'someone@spam.com',
            password= bcrypt.generate_password_hash('12345').decode('utf-8'),
        ),

    ]

    cards = [
        Card(
            title = 'Start the project',
            description = 'Stage 1 - Create the database',
            status = 'To Do',
            priority = 'High',
            date = date.today()
        ),
        Card(
            title = "SQLAlchemy",
            description = "Stage 2 - Integrate ORM",
            status = "Ongoing",
            priority = "High",
            date = date.today()
        ),
        Card(
            title = "ORM Queries",
            description = "Stage 3 - Implement several queries",
            status = "Ongoing",
            priority = "Medium",
            date = date.today()
        ),
        Card(
            title = "Marshmallow",
            description = "Stage 4 - Implement Marshmallow to jsonify models",
            status = "Ongoing",
            priority = "Medium",
            date = date.today()
        )
    ]
    db.session.add_all(users)
    db.session.add_all(cards)
    db.session.commit()
    print('Tables seeded')

# Terminal Response

# Legacy version
# @app.cli.command('all_cards')
# def all_cards():
#     # select * from cards;
#     cards = Card.query.all()
#     print(cards[0].__dict__)

# New version
@app.cli.command('all_cards')
def all_cards():
    # select * from cards;
    # stmt = db.select(Card).where(Card.status == 'To Do')
    # stmt = db.select(Card).filter_by(status= 'To Do')
    stmt = db.select(Card)
    cards = db.session.execute(stmt)
    print(cards)
    for card in cards:
        print(card)
    

# Legacy
# @app.cli.command('first_card')
# def first_card():
#     # select * from cards limit 1;
#     card = Card.query.first()
#     print(card.__dict__)

# New version
@app.cli.command('first_card')
def first_card():
    # select * from cards limit 1;
    stmt = db.select(Card).limit(1)
    card = db.session.scalar(stmt)
    print(card.__dict__)

@app.cli.command('count_ongoing')
def count_ongoing():
    stmt = db.select(db.func.count()).select_from(Card)
    print(stmt)
    cards = db.session.scalar(stmt)
    print(cards)
    # for card in cards:
    #     print(card.title, card.priority)

# Routed result

@app.route('/auth/login/', methods = ['POST'])
def auth_login():

    # Check if user exists and
    stmt = db.select(User).filter_by(email=request.json['email'])
    user = db.session.scalar(stmt)
    if user and bcrypt.check_password_hash(user.password,request.json['password']):
        # create token for client to store and use.
        token = create_access_token(identity= str(user.id), expires_delta=timedelta(days=1))
        return {'user': user.email, 'token': token, 'is_admin': user.is_admin}
    else:
        return {'error': 'Invalid email or password'}, 401

@app.route('/auth/register/', methods=['POST'])
def auth_register():
    try:
        # retrieve data from incoming POST request and parse the JSON
        # user_info = UserSchema().load(request.json)
        # Creat new user model instance from the user_info
        user = User(
            email = request.json['email'],
            password = bcrypt.generate_password_hash(request.json['password']).decode('utf-8'),
            name  = request.json['name']
        )

        # Add and commit user to DB
        db.session.add(user)
        db.session.commit()
        # Respond to Client DB info and Successful creation Code 201
        return UserSchema(exclude=['password']).dump(user), 201
    except IntegrityError:
        return {'error':'Email address already in use'}, 409


@app.route('/cards/')
@jwt_required()
def all_cards():
    # select * from cards;
    # stmt = db.select(Card).where(Card.status == 'To Do')
    # stmt = db.select(Card).filter_by(status= 'To Do')
    stmt = db.select(Card).order_by(Card.priority.desc(), Card.title)
    cards = db.session.scalars(stmt).all()
    return CardSchema(many=True).dump(cards)
    # for card in cards:
    #     print(card.title, card.priority)

@app.route('/')
def index():
    return "Whats up Doc!?"