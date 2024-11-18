from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum
from enum import Enum
from sqlalchemy import Enum as SaEnum

db = SQLAlchemy()

class Role(Enum):
    user = 'user'
    admin = 'admin'

class User(db.Model):
    __tablename__ = 'user'

    user_id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    gender = db.Column(db.String(10), nullable=False)    # Gunakan SaEnum dari sqlalchemy
    role = db.Column(SaEnum(Role), nullable=False)  # Gunakan SaEnum untuk role juga
    nickname = db.Column(db.String(50), nullable=True)
    profile_picture = db.Column(db.String(255), nullable=True) 

    def __init__(self, fullname, email, password, gender, role, nickname=None, otp=None, profile_picture=None):
        self.fullname = fullname
        self.email = email
        self.password = password
        self.gender = gender
        self.role = role
        self.nickname = nickname
        self.profile_picture = profile_picture



    def __repr__(self):
        return f'<User {self.name}>'
