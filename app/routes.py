from flask import Flask, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db, login_manager
from app.models import User
from flask_mail import Message
from app import mail
import secrets
from validators import url as url_validator
from requests.exceptions import ConnectionError, Timeout, RequestException
from run import hello
import requests

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Startseite
@app.route('/')
def home():
    
    return render_template('index.html')


@app.route('/crawl', methods=['GET'])
@login_required
def crawl_page():
    # Stellen Sie sicher, dass hier nur 'crawl.html' gerendert wird.
    return render_template('crawl.html')


#@app.route('/validate', methods=['GET'])
##@login_required
#def validate():
 #   return render_template('crawl.html')


# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    message = hello()
    print("Message from hello():", message) 
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            # Ändere die Weiterleitung zur neuen Crawl-Seite
            return redirect(url_for('crawl_page'))
        else:
            flash('Falsche Login-Daten!')
    
    return render_template('login.html')

def is_valid(url):
    """Überprüft, ob `url` eine gültige URL ist."""
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def get_all_links(url, soup):
    """Extrahiert und gibt alle Links von einer BeautifulSoup-Objekt zurück."""
    links = set()
    for link in soup.find_all('a', href=True):
        href = link['href']
        if is_valid(href):
            full_url = urljoin(url, href)
            links.add(full_url)
    return links

def crawl(url, max_depth):
    visited = set()  # Set to store visited URLs to avoid revisiting
    to_visit = [url]  # Starting with the initial URL

    while to_visit and max_depth > 0:
        current_url = to_visit.pop(0)
        if current_url not in visited:
            visited.add(current_url)
            try:
                response = requests.get(current_url, timeout=10)
                if response.ok:  # Checks if the response status code is less than 400
                    soup = BeautifulSoup(response.text, 'html.parser')
                    links = get_all_links(current_url, soup)
                    to_visit.extend(links - visited)  # Adds new links that haven't been visited
            except requests.RequestException as e:
                print(f"An error occurred: {e}")
        max_depth -= 1  # Reduces depth with each loop iteration

    return visited


@app.route('/start_crawl', methods=['POST'])
@login_required
def start_crawl():
    url = request.form['url']
    depth = int(request.form.get('depth', 1))
    links = []

    if not url_validator(url):
        flash('Ungültige URL. Bitte geben Sie eine gültige URL ein.', 'danger')
        return render_template('crawl.html', links=links)

    try:
        links = crawl(url, depth)
        flash(f'Die Webseite ist gültig und erreichbar! {len(links)} Links gefunden.', 'success')
    except Exception as e:
        flash(f'Ein Fehler ist aufgetreten: {str(e)}', 'danger')

    return render_template('crawl.html', links=links)




# Registrierung
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Email already exists.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)  # Using the default secure method
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'Error: Unable to register user. {str(e)}')
            return redirect(url_for('register'))

        login_user(new_user)  # Automatically log in the new user
        return redirect(url_for('home'))
    return render_template('register.html')




# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Passwort vergessen
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_password_token = token
            db.session.commit()
            
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset', sender='deyaa_yousef@yahoo.com', recipients=[user.email])
            msg.body = f'Visit this link to reset your password: {reset_link}'
            mail.send(msg)
            flash('An email with instructions to reset your password has been sent.')
            return redirect(url_for('login'))
        else:
            flash('No user found with that email address.')
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')


# Passwort zurücksetzen
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_password_token=token).first()
    if user:
        if request.method == 'POST':
            new_password = request.form.get('new_password')
            user.password = new_password
            user.reset_password_token = None  # Reset the token after password change
            db.session.commit()
            flash('Your password has been reset successfully.')
            return redirect(url_for('login'))
        return render_template('reset_password.html')
    else:
        flash('Invalid or expired token.')
        return redirect(url_for('forgot_password'))
