from flask import Flask, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db, login_manager
from app.models import User , CrawlData
from flask_mail import Message
from app import mail
import secrets
from validators import url as url_validator
from requests.exceptions import ConnectionError, Timeout, RequestException
from run import hello
import requests

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import aiohttp
import os;
import asyncio
from datetime import datetime



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

@app.route('/profile')
@login_required
def profile():
    # Fetch the crawl data for the current user, ordered by date descending
    crawl_records = CrawlData.query.filter_by(user_id=current_user.id).order_by(CrawlData.crawl_date.desc()).all()
    return render_template('profile.html', crawl_records=crawl_records)


async def fetch(session, url):
    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 404:
                print(f"URL not found: {url}")
                return None
            response.raise_for_status()
            content_type = response.headers.get('Content-Type', '').lower()
            if 'application/pdf' in content_type:
                filename = url.split('/')[-1]
                return (url, filename)
            elif 'text/html' in content_type:
                return await response.text()
            return None
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None
    
    
def is_valid(url):
    """Check if `url` is a valid URL."""
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme) and parsed.scheme in ['http', 'https']

def get_all_links(url, soup):
    """Extract and return all links from a BeautifulSoup object."""
    links = set()
    for link in soup.find_all('a', href=True):
        href = link['href']
        full_url = urljoin(url, href)
        if is_valid(full_url):
            links.add(full_url)
    return links

def find_pdf_links(url, soup):
    pdf_links = set()
    for link in soup.find_all('a', href=True):
        href = link['href']
        full_url = urljoin(url, href)
        if '.pdf' in full_url.lower():
            filename = full_url.split('/')[-1]
            pdf_links.add((full_url, filename))
    return pdf_links

async def download_pdf(session, url, user_id):
    filename = url.split('/')[-1]
    save_dir = f'downloads/{user_id}'
    os.makedirs(save_dir, exist_ok=True)
    save_path = os.path.join(save_dir, filename)
    try:
        async with session.get(url) as response:
            if response.status == 200:
                with open(save_path, 'wb') as f:
                    f.write(await response.read())
                return save_path
            else:
                print(f"Failed to download {url}: Status {response.status}")
    except Exception as e:
        print(f"Error downloading {url}: {e}")
    return None

# Modify the crawl function to download PDFs

async def crawl(url, level, user_id, session):
    visited = set()
    to_visit = [(url, 1)]
    all_pdf_links = set()
    base_domain = urlparse(url).netloc
    async with aiohttp.ClientSession() as session:
        while to_visit:
            current_url, current_depth = to_visit.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)
            content = await fetch(session, current_url)
            if isinstance(content, tuple):
                # Download the PDF and add to all_pdf_links if successful
                save_path = await download_pdf(session, content[0], user_id)
                if save_path:
                    all_pdf_links.add((content[0], content[1], save_path))
            elif isinstance(content, str):
                soup = BeautifulSoup(content, 'html.parser')
                pdf_links = find_pdf_links(current_url, soup)
                # Download each found PDF and update all_pdf_links
                for link, filename in pdf_links:
                    save_path = await download_pdf(session, link, user_id)
                    if save_path:
                        all_pdf_links.add((link, filename, save_path))
                if current_depth < level:
                    links = get_all_links(current_url, soup)
                    for link in links:
                        link_domain = urlparse(link).netloc
                        if (level == 2 and link_domain == base_domain) or level == 3:
                            to_visit.append((link, current_depth + 1))
    return visited, all_pdf_links


@app.route('/start_crawl', methods=['POST'])
@login_required
async def start_crawl():
    url = request.form['url']
    level = int(request.form.get('depth', 1))
    user_id = current_user.id

    async with aiohttp.ClientSession() as session:
        visited, pdf_links_tuples = await crawl(url, level, user_id, session)

    # Extract URLs and filenames for the template
    pdf_links_for_template = [{'url': link, 'filename': filename} for link, filename, _ in pdf_links_tuples]

    # Convert tuples to strings for storing in the database
    pdf_links_string = ','.join(f"{link}|{filename}" for link, filename, _ in pdf_links_tuples)
    pdf_paths_string = ','.join(f"{path}" for _, _, path in pdf_links_tuples)

    new_crawl = CrawlData(user_id=user_id, url=url, pdf_links=pdf_links_string, pdf_paths=pdf_paths_string, crawl_date=datetime.utcnow())
    db.session.add(new_crawl)
    db.session.commit()

    flash('Crawl erfolgreich gestartet. PDF-Links wurden gespeichert.')
    return render_template('crawl.html', visited=visited, pdf_links=pdf_links_for_template)




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




@app.route('/logout')
@login_required
def logout():
    try:
        # Delete all crawl records associated with the user
        CrawlData.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
    except Exception as e:
        # Log the error, possibly handle it or notify someone
        print(f"Error while deleting user data: {e}")

    # Clear the session and logout the user
    session.clear()
    logout_user()
    flash('All your data has been cleared and you have been logged out.')
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
