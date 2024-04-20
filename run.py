from app import app
from flask import Flask, current_app

app = Flask(__name__)

def hello():
   secret_key = current_app.config['SECRET_KEY']
   return f'The secret key is: {secret_key}'

if __name__ == '__main__':
    app.run(debug=True)
