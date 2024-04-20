from flask import Flask, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db, login_manager
from app.models import User
from flask_mail import Message
from app import mail
import secrets

from run import hello



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Startseite
@app.route('/')
def home():
    
    return render_template('index.html')

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
        
        # Prüfe, ob der Benutzer existiert und das Passwort korrekt ist
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            return redirect(url_for('home'))
        else:
            flash('Falsche Login-Daten!')
    
    return render_template('login.html')

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
