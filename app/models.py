import itsdangerous
from app import db
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import current_app
import secrets
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    crawl_data = db.relationship('CrawlData', backref='user', lazy=True)

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


class CrawlData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(512), nullable=False)
    crawl_date = db.Column(db.DateTime, default=datetime.utcnow)
    pdf_links = db.Column(db.Text)  # Speichert PDF-Links als durch Kommata getrennten String

    def __repr__(self):
        return f'<CrawlData {self.url}>'
    

class PDFFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    crawl_id = db.Column(db.Integer, db.ForeignKey('crawl_data.id'))
    file_path = db.Column(db.String(2048))
    accessed_date = db.Column(db.DateTime)






