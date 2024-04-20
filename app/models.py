import itsdangerous
from app import db
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import current_app
import secrets


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def get_reset_password_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=1800)
            user_id = data['user_id']
            return User.query.get(user_id)
        except itsdangerous.SignatureExpired:
            # Token expired
            return None
        except itsdangerous.BadSignature:
            # Invalid or tampered token
            return None
        except Exception as e:
            # Other unexpected errors
            print(f"Error verifying token: {e}")
            return None




