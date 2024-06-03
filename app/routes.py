from flask import Flask, jsonify, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db, login_manager
from app.models import User, CrawlData
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
import os
import asyncio
from datetime import datetime
import re
from collections import Counter
import PyPDF2
import logging


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/crawl', methods=['GET'])
@login_required
def crawl_page():
    return render_template('crawl.html')


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
            return redirect(url_for('crawl_page'))
        else:
            flash('Falsche Login-Daten!')

    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    crawl_records = CrawlData.query.filter_by(user_id=current_user.id).order_by(CrawlData.crawl_date.desc()).all()

    for record in crawl_records:
        word_stats_list = []
        for stat in record.word_stats.split(';'):
            if '|' in stat:
                pdf_url, word_counts = stat.split('|', 1)
                word_count_pairs = word_counts.split(',')
                word_counts_dict = {}
                for word_count in word_count_pairs:
                    parts = word_count.split(':')
                    if len(parts) == 2:
                        word, count = parts
                        try:
                            word_counts_dict[word] = int(count)
                        except ValueError:
                            continue
                
                max_word, max_count = None, 0
                for word, count in word_counts_dict.items():
                    if count > max_count:
                        max_word, max_count = word, count
                
                word_stats_list.append({'pdf_url': pdf_url, 'word_counts': word_counts_dict, 'max_word': max_word, 'max_count': max_count})
        
        record.parsed_word_stats = word_stats_list

    return render_template('profile.html', crawl_records=crawl_records, enumerate=enumerate)








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
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme) and parsed.scheme in ['http', 'https']


def get_all_links(url, soup):
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


def extract_text_from_pdf(pdf_path):
    try:
        with open(pdf_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            text = ""
            for page in reader.pages:
                text += page.extract_text()
            return text
    except Exception as e:
        print(f"Error extracting text from {pdf_path}: {e}")
        return ""


def get_word_frequency(text):
    words = re.findall(r'\b[a-zA-ZäöüÄÖÜß]{2,}\b', text.lower())  # Wörter mit mindestens zwei Buchstaben
    word_counts = Counter(words)
    most_common_words = word_counts.most_common(10)
    print(f"Most common words: {most_common_words}")  # Debugging-Ausgabe
    return most_common_words


async def crawl(url, level, user_id):
    visited = set()
    to_visit = [(url, 1)]
    all_pdf_links = set()
    base_domain = urlparse(url).netloc
    word_stats = {}

    async with aiohttp.ClientSession() as session:
        while to_visit:
            current_url, current_depth = to_visit.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)
            content = await fetch(session, current_url)
            if isinstance(content, tuple):
                save_path = await download_pdf(session, content[0], user_id)
                if save_path:
                    all_pdf_links.add((content[0], content[1], save_path))
                    text = extract_text_from_pdf(save_path)
                    word_stats[content[0]] = get_word_frequency(text)
            elif isinstance(content, str):
                soup = BeautifulSoup(content, 'html.parser')
                pdf_links = find_pdf_links(current_url, soup)
                for link, filename in pdf_links:
                    save_path = await download_pdf(session, link, user_id)
                    if save_path:
                        all_pdf_links.add((link, filename, save_path))
                        text = extract_text_from_pdf(save_path)
                        word_stats[link] = get_word_frequency(text)
                if current_depth < level:
                    links = get_all_links(current_url, soup)
                    for link in links:
                        link_domain = urlparse(link).netloc
                        if (level == 2 and link_domain == base_domain) or level == 3:
                            to_visit.append((link, current_depth + 1))
    return visited, all_pdf_links, word_stats

@app.route('/start_crawl', methods=['POST'])
@login_required
async def start_crawl():
    url = request.form['url']
    level = int(request.form.get('depth', 1))
    user_id = current_user.id

    visited, pdf_links_tuples, word_stats = await crawl(url, level, user_id)

    pdf_links_for_template = [{'url': link, 'filename': filename} for link, filename, _ in pdf_links_tuples]
    pdf_links_string = ','.join(f"{link}|{filename}" for link, filename, _ in pdf_links_tuples)
    pdf_paths_string = ','.join(f"{path}" for _, _, path in pdf_links_tuples)
    word_stats_string = ';'.join(f"{link}|{','.join(f'{word}:{count}' for word, count in stats)}" for link, stats in word_stats.items())

    if not pdf_links_tuples:
        pdf_links_string = "no_pdfs_found"
        word_stats_string = ""

    new_crawl = CrawlData(
        user_id=user_id,
        url=url,
        pdf_links=pdf_links_string,
        pdf_paths=pdf_paths_string,
        word_stats=word_stats_string,
        crawl_date=datetime.utcnow()
    )
    db.session.add(new_crawl)
    db.session.commit()

    flash('Crawl erfolgreich gestartet. PDF-Links wurden gespeichert.')
    return render_template('crawl.html', visited=visited, pdf_links=pdf_links_for_template)




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

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'Error: Unable to register user. {str(e)}')
            return redirect(url_for('register'))

        login_user(new_user)
        return redirect(url_for('home'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    try:
        CrawlData.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
    except Exception as e:
        print(f"Error while deleting user data: {e}")

    session.clear()
    logout_user()
    flash('All your data has been cleared and you have been logged out.')
    return redirect(url_for('home'))


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


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_password_token=token).first()
    if user:
        if request.method == 'POST':
            new_password = request.form.get('new_password')
            user.password = new_password
            user.reset_password_token = None
            db.session.commit()
            flash('Your password has been reset successfully.')
            return redirect(url_for('login'))
        return render_template('reset_password.html')
    else:
        flash('Invalid or expired token.')
        return redirect(url_for('forgot_password'))


@app.route('/search_word', methods=['POST'])
@login_required
def search_word():
    search_word = request.form.get('search_word').lower()
    matching_pdfs = []

    crawl_records = CrawlData.query.filter_by(user_id=current_user.id).all()

    for record in crawl_records:
        word_stats_list = []
        pdf_url_to_stats = {}
        for stat in record.word_stats.split(';'):
            if '|' in stat:
                pdf_url, word_counts = stat.split('|', 1)
                word_count_pairs = word_counts.split(',')
                word_counts_dict = {}
                for word_count in word_count_pairs:
                    parts = word_count.split(':')
                    if len(parts) == 2:
                        word, count = parts
                        try:
                            word_counts_dict[word] = int(count)
                        except ValueError:
                            continue
                pdf_url_to_stats[pdf_url] = word_counts_dict
        record.parsed_word_stats = pdf_url_to_stats

    for record in crawl_records:
        for pdf_url, word_counts in record.parsed_word_stats.items():
            if search_word in word_counts:
                matching_pdfs.append({
                    'pdf_url': pdf_url,
                    'record_url': record.url,
                    'word': search_word,
                    'count': word_counts[search_word]
                })

    return render_template('profile.html', crawl_records=crawl_records, search_results=matching_pdfs, enumerate=enumerate)


@app.route('/debug/word_stats')
@login_required
def debug_word_stats():
    crawl_records = CrawlData.query.filter_by(user_id=current_user.id).all()
    debug_info = []
    for record in crawl_records:
        debug_info.append({
            'id': record.id,
            'url': record.url,
            'word_stats': record.word_stats
        })
    return jsonify(debug_info)


@app.route('/check_data')
@login_required
def check_data():
    crawl_records = CrawlData.query.filter_by(user_id=current_user.id).all()
    data = []
    for record in crawl_records:
        data.append({
            'id': record.id,
            'url': record.url,
            'word_stats': record.word_stats,
        })
    return jsonify(data)


# Import statement for PDFPage
from pdfminer.pdfpage import PDFPage

# Update the extract_text_from_pdf function to use pdfminer
def extract_text_from_pdf(pdf_path):
    try:
        from io import StringIO
        from pdfminer.high_level import extract_text_to_fp
        from pdfminer.layout import LAParams
        from pdfminer.pdfinterp import PDFResourceManager
        from pdfminer.converter import TextConverter

        output_string = StringIO()
        with open(pdf_path, 'rb') as file:
            extract_text_to_fp(file, output_string, laparams=LAParams(), output_type='text', codec=None)
        text = output_string.getvalue()
        print(f"Extracted text from {pdf_path}: {text[:500]}")  # Print the first 500 characters for inspection
        return text
    except Exception as e:
        print(f"Error extracting text from {pdf_path}: {e}")
        return ""
