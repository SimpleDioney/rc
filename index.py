# Flask setup
from flask import Flask, jsonify, flash, request, send_file, Response, render_template, redirect, url_for, session as flask_session, render_template_string, current_app
from flask_cors import CORS

# Security and authentication
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

# Database and ORM
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, desc, func, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime, timedelta

# Utilities
import requests
from functools import wraps
from bs4 import BeautifulSoup
import pytz
from pytz import timezone
import urllib.parse
import re
import time
import concurrent.futures
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import os
import json
import hashlib
from io import StringIO
import csv
import logging

app = Flask(__name__)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.secret_key = 'Dioneyyy'
Base = declarative_base()
engine = create_engine('sqlite:///cache.db')
Session = sessionmaker(bind=engine)

# Database models
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    is_admin = Column(Boolean, default=False)
    admin_level = Column(Integer, default=0)
    admin_password = Column(String(100))  # Nova coluna para senha de admin
    created_by = Column(Integer, ForeignKey('users.id'))
    created_admins = relationship('User', backref='creator', remote_side=[id])
    viewing_history = relationship('ViewingHistory', back_populates='user')
    is_super_admin = Column(Boolean, default=False)

class CacheEntry(Base):
    __tablename__ = 'cache_entries'
    id = Column(Integer, primary_key=True)
    url = Column(String, unique=True, nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.now(pytz.timezone('America/Sao_Paulo')))

class RecentActivity(Base):
    __tablename__ = 'recent_activities'
    id = Column(Integer, primary_key=True)
    activity_type = Column(String(50), nullable=False)
    description = Column(String(255), nullable=False)
    timestamp = Column(DateTime, default=datetime.now(pytz.timezone('America/Sao_Paulo')))

class ViewingHistory(Base):
    __tablename__ = 'viewing_history'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    video_url = Column(String, nullable=False)
    video_title = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.now(pytz.timezone('America/Sao_Paulo')))
    user = relationship('User', back_populates='viewing_history')

def get_cache_key(url):
    return hashlib.md5(url.encode()).hexdigest()

def get_cached_content(url):
    db_session = Session()
    cache_entry = db_session.query(CacheEntry).filter_by(url=url).first()
    if cache_entry and datetime.utcnow() - cache_entry.timestamp < timedelta(hours=1):
        db_session.close()
        return cache_entry.content
    db_session.close()
    return None

def save_to_cache(url, content):
    db_session = Session()
    cache_entry = db_session.query(CacheEntry).filter_by(url=url).first()
    if cache_entry:
        cache_entry.content = content
        cache_entry.timestamp = datetime.utcnow()
    else:
        new_entry = CacheEntry(url=url, content=content)
        db_session.add(new_entry)
    db_session.commit()
    db_session.close()
    log_activity('cache', f'Cache entry added: {url}')

Base.metadata.create_all(engine)

# Helper functions
def log_activity(activity_type, description):
    db_session = Session()
    new_activity = RecentActivity(activity_type=activity_type, description=description)
    db_session.add(new_activity)
    db_session.commit()
    db_session.close()

def create_super_admin(app):
    with app.app_context():
        db_session = Session()
        super_admin = db_session.query(User).filter_by(is_super_admin=True).first()
        if not super_admin:
            username = 'Dioney'
            password = 'Dioney13'  # Substitua por uma senha forte
            hashed_password = generate_password_hash(password)
            super_admin = User(
                username=username,
                password=hashed_password,
                is_admin=True,
                admin_level=99999,  # Um nível muito alto
                is_super_admin=True
            )
            db_session.add(super_admin)
            db_session.commit()
            print(f"Super Admin criado: {username}")
        db_session.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in flask_session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def check_auth(username, password):
    db_session = Session()
    user = db_session.query(User).filter_by(username=username).first()
    db_session.close()
    if user and user.is_super_admin:
        return check_password_hash(user.password, password)
    return username == 'Dioney' and password == 'Dioney13'
    
def authenticate():
    return Response(
        'Autenticação necessária', 401,
        {'WWW-Authenticate': 'Basic realm="Login necessário"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def create_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

session = create_session()

# Scraper

def get_content(url, timeout=5):
    cached_content = get_cached_content(url)
    if cached_content:
        print(f"Usando cache para {url}")
        return BeautifulSoup(cached_content, "html.parser")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    start_time = time.time()
    try:
        response = session.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        content = response.text
        save_to_cache(url, content)
    except requests.RequestException as e:
        print(f"Erro ao fazer a requisição para {url}: {e}")
        return None
    end_time = time.time()
    print(f"Requisição para {url} levou {end_time - start_time:.2f} segundos.")
    return BeautifulSoup(content, "html.parser")


def get_video_options(soup):
    options = []
    for thumbnail in soup.select('div.thumbnail'):
        caption = thumbnail.select_one('div.caption')
        if caption:
            h3 = caption.select_one('h3')
            if h3:
                a_tag = h3.select_one('a')
                if a_tag:
                    title = a_tag.text.strip()
                    link = a_tag['href']
                    
                    # Extract cover image URL
                    img_tag = thumbnail.select_one('img[data-echo]')
                    cover_image = img_tag['data-echo'] if img_tag else None
                    
                    options.append({'title': title, 'link': link, 'cover_image': cover_image})
    return options

def get_total_pages(soup):
    pagination = soup.select_one('ul.pagination')
    if pagination:
        last_page = pagination.select('li')[-2].select_one('a')
        if last_page and last_page.text.isdigit():
            return int(last_page.text)
    return 1

def get_video_embed(url):
    soup = get_content(url)
    if not soup:
        return None
    iframe = soup.select_one('iframe[name="Player"]')
    return iframe['src'] if iframe and 'src' in iframe.attrs else None

def fetch_page(url):
    soup = get_content(url)
    if soup:
        options = get_video_options(soup)
        # Filtra os resultados com "Lista de Episódios" no título
        filtered_options = [option for option in options if "Lista de Episódios" not in option['title']]
        return filtered_options
    return []

def prefetch_pages(urls):
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        executor.map(fetch_page, urls)

def sort_videos(videos):
    def extract_season_episode(title):
        match = re.search(r'(\d+)ª\s*Temporada\s*-\s*Episódio\s*(\d+)', title)
        if match:
            return int(match.group(1)), int(match.group(2))
        return 0, 0

    return sorted(videos, key=lambda x: extract_season_episode(x['title']))

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db_session = Session()
        existing_user = db_session.query(User).filter_by(username=username).first()
        if existing_user:
            db_session.close()
            return "Nome de usuário já existe", 400
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db_session.add(new_user)
        db_session.commit()
        db_session.close()
        log_activity('register', f'User registered: {username}')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db_session = Session()
        user = db_session.query(User).filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            flask_session['user_id'] = user.id  # Aqui o user_id é armazenado na sessão
            flask_session.permanent = True
            db_session.close()
            log_activity('login', f'User login: {username}')
            return redirect(url_for('index'))
        
        db_session.close()
        return "Nome de usuário ou senha inválidos", 401
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    flask_session.clear()
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST', 'DELETE'])
@requires_auth
def admin():
    db_session = Session()

    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            cache_entry = db_session.query(CacheEntry).filter_by(url=url).first()
            if cache_entry:
                db_session.delete(cache_entry)
                db_session.commit()
                flash('Cache entry deleted successfully', 'success')
                log_activity('delete', f'Cache entry deleted: {url}')
            else:
                flash('Cache entry not found', 'error')
        return redirect(url_for('admin'))

    entries = db_session.query(CacheEntry).all()
    total_users = db_session.query(User).count()
    total_cache_entries = db_session.query(CacheEntry).count()
    total_history_entries = db_session.query(ViewingHistory).count()

    recent_activities = db_session.query(RecentActivity).order_by(RecentActivity.timestamp.desc()).limit(5).all()

    sao_paulo_tz = pytz.timezone('America/Sao_Paulo')
    for activity in recent_activities:
        activity.timestamp = activity.timestamp.replace(tzinfo=pytz.UTC).astimezone(sao_paulo_tz)

    db_session.close()

    return render_template('admin.html', 
                           entries=entries, 
                           total_users=total_users, 
                           total_cache_entries=total_cache_entries, 
                           total_history_entries=total_history_entries,
                           recent_activities=recent_activities)

@app.route('/admin/add', methods=['POST'])
@requires_auth
def add_admin():
    modifier_id = flask_session.get('user_id')
    target_username = request.json.get('username')
    admin_password = request.json.get('password')
    admin_level = request.json.get('admin_level', 1)

    # Converta admin_level para int
    try:
        admin_level = int(admin_level)
    except ValueError:
        return jsonify({"error": "Invalid admin_level format"}), 400

    # Logging para depuração
    app.logger.info(f"Modifier ID: {modifier_id}")
    app.logger.info(f"Received Data: username={target_username}, password={admin_password}, admin_level={admin_level}")

    # Verificar se o usuário está autenticado
    if not modifier_id:
        app.logger.error("User not authenticated")
        return jsonify({"error": "User not authenticated"}), 400

    if not all([modifier_id, target_username, admin_password]):
        app.logger.error("Missing required information")
        return jsonify({"error": "Missing required information"}), 400

    db_session = Session()
    try:
        modifier = db_session.query(User).get(modifier_id)
        target = db_session.query(User).filter_by(username=target_username).first()

        if not modifier or not target:
            return jsonify({"error": "User not found"}), 404

        if not modifier.is_admin or modifier.admin_level <= admin_level:
            app.logger.error(f"Insufficient permissions for user {modifier.username}")
            return jsonify({"error": "Insufficient permissions"}), 403

        if target.is_admin:
            app.logger.error(f"User {target.username} is already an admin")
            return jsonify({"error": "User is already an admin"}), 400

        target.is_admin = True
        target.admin_level = admin_level
        target.admin_password = generate_password_hash(admin_password)
        target.created_by = modifier.id

        db_session.commit()
        log_activity('add_admin', f'Admin added: {target.username} (Level {admin_level}) by {modifier.username}')
        app.logger.info(f"Admin {target.username} added successfully")
        return jsonify({"message": f"{target.username} is now an admin with level {admin_level}"}), 200

    except Exception as e:
        db_session.rollback()
        app.logger.error(f"Error during admin addition: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()


@app.route('/admin/remove', methods=['POST'])
@requires_auth
def remove_admin():
    modifier_id = flask_session.get('user_id')
    target_username = request.json.get('username')

    db_session = Session()
    try:
        modifier = db_session.query(User).get(modifier_id)
        target = db_session.query(User).filter_by(username=target_username).first()

        if not modifier or not target:
            return jsonify({"error": "User not found"}), 404

        if target.is_super_admin:
            return jsonify({"error": "Cannot modify Super Admin"}), 403

        if not can_modify_admin(modifier, target):
            return jsonify({"error": "Insufficient permissions"}), 403

        target.is_admin = False
        target.admin_level = 0
        target.created_by = None

        db_session.commit()
        log_activity('remove_admin', f'Admin removed: {target.username} by {modifier.username}')
        return jsonify({"message": f"{target.username} is no longer an admin"}), 200

    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()

@app.route('/admin/list', methods=['GET'])
@requires_auth
def list_admins():
    db_session = Session()
    try:
        admins = db_session.query(User).filter(User.is_admin == True).all()
        admin_list = [{
            "id": admin.id,
            "username": admin.username,
            "admin_level": admin.admin_level,
            "created_by": db_session.query(User).get(admin.created_by).username if admin.created_by else None
        } for admin in admins]
        return jsonify(admin_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()

@app.route('/admin/all_users')
@requires_auth
def list_all_users():
    db_session = Session()
    try:
        current_user = db_session.query(User).get(flask_session.get('user_id'))
        if not current_user or not current_user.is_super_admin:
            return jsonify({"error": "Insufficient permissions"}), 403

        users = db_session.query(User).all()
        user_list = [{
            "id": user.id,
            "username": user.username,
            "is_admin": user.is_admin,
            "admin_level": user.admin_level,
            "is_super_admin": user.is_super_admin
        } for user in users]
        return jsonify(user_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()

@app.route('/admin/verify_password', methods=['POST'])
@requires_auth
def verify_admin_password():
    admin_id = request.json.get('admin_id')
    password = request.json.get('password')

    if not admin_id or not password:
        return jsonify({"error": "Missing admin ID or password"}), 400

    db_session = Session()
    try:
        admin = db_session.query(User).get(admin_id)
        if not admin or not admin.is_admin:
            return jsonify({"error": "Admin not found"}), 404

        if check_password_hash(admin.admin_password, password):
            return jsonify({"message": "Password verified"}), 200
        else:
            return jsonify({"error": "Invalid password"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()

@app.route('/admin/clear_cache', methods=['POST'])
@requires_auth
def clear_cache():
    db_session = Session()
    try:
        db_session.query(CacheEntry).delete()
        db_session.commit()
        log_activity('clear_cache', 'All cache entries cleared')
        flash('Cache cleared successfully', 'success')
    except Exception as e:
        db_session.rollback()
        flash(f'Error clearing cache: {str(e)}', 'error')
    finally:
        db_session.close()
    return redirect(url_for('admin'))

@app.route('/admin/download_logs')
@requires_auth
def download_logs():
    tz = timezone('America/Sao_Paulo')
    db_session = Session()
    activities = db_session.query(RecentActivity).order_by(RecentActivity.timestamp.desc()).all()
    db_session.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Activity Type', 'Description'])
    for activity in activities:
        activity_time = activity.timestamp.astimezone(tz)
        writer.writerow([activity_time.strftime('%Y-%m-%d %H:%M:%S'), activity.activity_type, activity.description])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            "Content-Disposition": "attachment;filename=activity_logs.csv"
        }
    )

@app.route('/admin/users')
@requires_auth
def list_users():
    db_session = Session()
    users = db_session.query(User).all()
    db_session.close()
    return render_template('users.html', users=users)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@requires_auth
def delete_user(user_id):
    db_session = Session()
    user = db_session.query(User).get(user_id)
    if user:
        db_session.delete(user)
        db_session.commit()
        log_activity('delete_user', f'User deleted: {user.username}')
        flash(f'User {user.username} deleted successfully', 'success')
    else:
        flash('User not found', 'error')
    db_session.close()
    return redirect(url_for('list_users'))

@app.route('/search', methods=['GET'])
@login_required
def search_videos():
    search_term = request.args.get('query')
    page = request.args.get('page', 1, type=int)  # Página atual (padrão 1)

    if not search_term:
        return jsonify({"error": "Query parameter is required"}), 400
    
    # Construir a URL base com o termo de pesquisa e página atual
    if page == 1:
        base_url = f"https://redecanais.tw/tags/{urllib.parse.quote(search_term)}/"
    else:
        base_url = f"https://redecanais.tw/tags/{urllib.parse.quote(search_term)}/page-{page}/"

    # Fazer o scrape da página atual
    soup = get_content(base_url)
    if not soup:
        return jsonify({"error": "Erro ao carregar a página inicial."}), 500

    total_pages = get_total_pages(soup)
    
    # Buscar vídeos na página atual
    options = fetch_page(base_url)

    # Ordenar os vídeos
    sorted_options = sort_videos(options)

    return jsonify({
        "current_page": page,
        "total_pages": total_pages,
        "videos": sorted_options
    })

@app.route('/embed', methods=['GET'])
@login_required
def get_embed():
    video_url = request.args.get('url')
    video_title = request.args.get('title')
    if not video_url or not video_title:
        logger.error("URL ou título do vídeo não fornecidos")
        return jsonify({"error": "URL e título do vídeo são obrigatórios."}), 400

    embed_url = get_video_embed(video_url)
    if not embed_url:
        logger.error(f"Não foi possível encontrar o embed para a URL: {video_url}")
        return jsonify({"error": "Não foi possível encontrar o embed do vídeo."}), 500

    # Use the updated save_to_history function
    save_to_history(video_url, video_title)

    return jsonify({"embed_url": embed_url})

@app.route('/history')
@login_required
def viewing_history():
    return render_template('history.html')

@app.route('/get_history')
@login_required
def get_history():
    user_id = flask_session.get('user_id')
    if not user_id:
        logger.error("Tentativa de acessar histórico sem user_id na sessão")
        return jsonify({"error": "Usuário não autenticado"}), 401

    db_session = Session()
    try:
        history = db_session.query(ViewingHistory)\
            .filter_by(user_id=user_id)\
            .order_by(ViewingHistory.timestamp.desc())\
            .all()
        
        history_data = [
            {
                "video_title": item.video_title,
                "video_url": item.video_url,
                "timestamp": item.timestamp.isoformat()
            } for item in history
        ]
        
        return jsonify(history_data)
    except SQLAlchemyError as e:
        logger.error(f"Erro ao buscar histórico: {str(e)}")
        return jsonify({"error": "Erro ao buscar o histórico"}), 500
    finally:
        db_session.close()

def save_to_history(video_url, video_title):
    user_id = flask_session.get('user_id')
    if not user_id:
        logger.error("Tentativa de salvar histórico sem user_id na sessão")
        return

    db_session = Session()
    try:
        # Defina o fuso horário para São Paulo
        brasil_tz = pytz.timezone('America/Sao_Paulo')
        current_time = datetime.now(brasil_tz)

        # Verificar se uma entrada com o mesmo título já existe
        existing_entry = db_session.query(ViewingHistory).filter_by(
            user_id=user_id, 
            video_title=video_title
        ).first()

        if existing_entry:
            # Atualizar o timestamp da entrada existente
            existing_entry.timestamp = current_time
            logger.info(f"Histórico atualizado: user_id={user_id}, url={video_url}, title={video_title}")
        else:
            # Criar uma nova entrada se não existir
            new_history = ViewingHistory(user_id=user_id, video_url=video_url, video_title=video_title, timestamp=current_time)
            db_session.add(new_history)
            logger.info(f"Novo histórico salvo: user_id={user_id}, url={video_url}, title={video_title}")

        db_session.commit()
    except SQLAlchemyError as e:
        db_session.rollback()
        logger.error(f"Erro ao salvar no banco de dados: {str(e)}")
    finally:
        db_session.close()

@app.route('/proxy')
@login_required
def proxy():
    video_url = request.args.get('url')
    video_title = request.args.get('title', 'Título não disponível')
    
    if not video_url:
        logger.error(f"Requisição de proxy inválida: url={video_url}")
        return jsonify({"error": "URL is required"}), 400
    
    video_embed_url = get_video_embed(video_url)
    
    if not video_embed_url:
        logger.error(f"Não foi possível obter o vídeo embed para: {video_url}")
        return jsonify({"error": "Não foi possível obter o vídeo embed"}), 500
    
    # Ajuste na URL do vídeo embed
    parsed_url = urllib.parse.urlparse(video_embed_url)
    adjusted_url = urllib.parse.urlunparse(parsed_url._replace(netloc="redecanais.tw"))
    
    # Use the updated save_to_history function
    save_to_history(video_url, video_title)
    
    return jsonify({"embed_url": adjusted_url})

if __name__ == "__main__":
    create_super_admin(app)
    app.run(debug=True)