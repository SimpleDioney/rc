# Flask setup
from flask import Flask, jsonify, flash, request, send_file, Response
from flask import render_template, redirect, url_for, session as flask_session
from flask import render_template_string, current_app
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_compress import Compress

# Security and authentication
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from functools import wraps

# Database and ORM
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, desc, func, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship, sessionmaker, scoped_session
from sqlalchemy.pool import QueuePool

# Date and time
from datetime import datetime, timedelta
import pytz
from pytz import timezone
import time

# Web scraping and networking
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import urllib.parse
import cloudscraper
from fake_useragent import UserAgent
import dns.resolver
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Utilities
import os
import json
import hashlib
import logging
import re
import csv
from io import StringIO
import concurrent.futures
from pathlib import Path
from dotenv import load_dotenv
import random

# Load environment variables
load_dotenv()

# Configuration class
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
    FLASK_ENV = os.getenv('FLASK_ENV', 'production')
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///cache.db')
    AWS_REGION = os.getenv('AWS_REGION', 'sa-east')
    PERMANENT_SESSION_LIFETIME = timedelta(days=365)
    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = '/tmp/flask_session'
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    RATE_LIMIT = os.getenv('RATE_LIMIT', '200 per minute')
    COMPRESS_LEVEL = 6
    COMPRESS_ALGORITHM = ['br', 'gzip', 'deflate']
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
CORS(app, resources={r"/*": {"origins": "*"}})
Compress(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[Config.RATE_LIMIT]
)

# Configure logging
logging.basicConfig(level=getattr(logging, Config.LOG_LEVEL))
logger = logging.getLogger(__name__)

if not app.debug:
    log_dir = Path("/var/log/videohub")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / 'app.log',
        maxBytes=10485760,  # 10MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('VideoHub startup')

# Initialize database
Base = declarative_base()
engine = create_engine(
    Config.DATABASE_URL,
    poolclass=QueuePool,
    pool_size=20,
    max_overflow=0,
    pool_pre_ping=True,
    pool_recycle=3600
)
Session = scoped_session(sessionmaker(bind=engine))

# Initialize global session variable
persistent_session = None

# Database Models
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    is_admin = Column(Boolean, default=False)
    admin_level = Column(Integer, default=0)
    admin_password = Column(String(100))
    created_by = Column(Integer, ForeignKey('users.id'))
    created_admins = relationship('User', backref='creator', remote_side=[id])
    viewing_history = relationship('ViewingHistory', back_populates='user')
    is_super_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(pytz.UTC))
    last_login = Column(DateTime)
    is_active = Column(Boolean, default=True)

class CacheEntry(Base):
    __tablename__ = 'cache_entries'
    id = Column(Integer, primary_key=True)
    url = Column(String, unique=True, nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(pytz.UTC))
    hits = Column(Integer, default=0)
    last_accessed = Column(DateTime)

class RecentActivity(Base):
    __tablename__ = 'recent_activities'
    id = Column(Integer, primary_key=True)
    activity_type = Column(String(50), nullable=False)
    description = Column(String(255), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(pytz.timezone('America/Sao_Paulo')))
    user_id = Column(Integer, ForeignKey('users.id'))
    ip_address = Column(String(45))
    user_agent = Column(String(255))

class ViewingHistory(Base):
    __tablename__ = 'viewing_history'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    content_type = Column(String, nullable=False)
    title = Column(String, nullable=False)
    episodes = Column(JSON)
    url = Column(String)
    last_watched = Column(DateTime, default=lambda: datetime.now(pytz.timezone('America/Sao_Paulo')))
    watch_count = Column(Integer, default=1)
    user = relationship('User', back_populates='viewing_history')

# Helper Functions
def configure_dns():
    """Configure DNS resolver to use Cloudflare's DNS"""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']
    return resolver

dns_resolver = configure_dns()

class CloudflareHTTPAdapter(HTTPAdapter):
    """Custom HTTP adapter for Cloudflare"""
    def __init__(self, *args, **kwargs):
        self.dns_resolver = kwargs.pop('dns_resolver', dns_resolver)
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        parsed_url = urllib.parse.urlparse(request.url)
        try:
            answer = self.dns_resolver.resolve(parsed_url.hostname, 'A')
            ip = str(answer[0])
            url_with_ip = parsed_url._replace(netloc=ip).geturl()
            request.url = url_with_ip
            request.headers['Host'] = parsed_url.hostname
        except Exception as e:
            logger.error(f"DNS resolution error: {str(e)}")
        return super().send(request, **kwargs)

def create_persistent_session():
    """Create a persistent session with custom settings"""
    scraper = cloudscraper.create_scraper(
        browser={
            'browser': 'chrome',
            'platform': 'windows',
            'desktop': True
        },
        delay=10
    )
    
    ua = UserAgent()
    default_headers = {
        'User-Agent': ua.random,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
    }
    
    scraper.headers.update(default_headers)
    return scraper

def initialize_session():
    """Initialize the global session"""
    global persistent_session
    persistent_session = create_persistent_session()

# Initialize session at module level
initialize_session()

def get_cache_key(url):
    """Generate a cache key for a URL"""
    return hashlib.md5(url.encode()).hexdigest()

def get_cached_content(url):
    """Retrieve cached content for a URL"""
    db_session = Session()
    try:
        cache_entry = db_session.query(CacheEntry).filter_by(url=url).first()
        current_time = datetime.now(pytz.UTC)
        
        if cache_entry and (current_time - cache_entry.timestamp.replace(tzinfo=pytz.UTC)) < timedelta(hours=1):
            cache_entry.hits += 1
            cache_entry.last_accessed = current_time
            db_session.commit()
            return cache_entry.content
        return None
    finally:
        db_session.close()

def save_to_cache(url, content):
    """Save content to cache"""
    db_session = Session()
    try:
        current_time = datetime.now(pytz.UTC)
        cache_entry = db_session.query(CacheEntry).filter_by(url=url).first()
        
        if cache_entry:
            cache_entry.content = content
            cache_entry.timestamp = current_time
            cache_entry.hits += 1
            cache_entry.last_accessed = current_time
        else:
            new_entry = CacheEntry(
                url=url,
                content=content,
                timestamp=current_time,
                last_accessed=current_time
            )
            db_session.add(new_entry)
        
        db_session.commit()
        log_activity('cache', f'Cache entry added/updated: {url}')
    except Exception as e:
        db_session.rollback()
        logger.error(f"Error saving to cache: {str(e)}")
        raise
    finally:
        db_session.close()

def is_series(title):
    """Check if content is a series based on title"""
    return bool(re.search(r'temporada|season', title, re.IGNORECASE))

def format_title(title):
    """Format title consistently"""
    match = re.search(r'^(.*?)\s*(\d+)\s*ª?\s*Temporada\s*.*?-\s*(\d+)\s*–?\s*(.*)$', title)
    if match:
        show_name = match.group(1).strip()
        season = match.group(2).strip()
        episode = match.group(3).strip()
        episode_name = match.group(4).strip()
        return f"{show_name} - {season}ª Temporada (Legendado) - Episódio {episode.zfill(2)} - {episode_name}"
    return title

def extract_season_episode(title):
    """Extract season and episode numbers from title"""
    formatted_title = format_title(title)
    match = re.search(r'(\d+)\s*ª?\s*Temporada.*?[-–]?\s*Episódio\s*(\d+)|'
                     r'(\d+)\s*ª?\s*Episódio\s*(\d+)|'
                     r'(\d+)\s*ª?\s*T\s*[-–]?\s*(\d+)',
                     formatted_title)
    
    if match:
        season = int(match.group(1) or match.group(3) or match.group(5) or 0)
        episode = int(match.group(2) or match.group(4) or match.group(6) or 0)
        return season, episode
    return 0, 0

# Authentication and Authorization Functions
def create_super_admin(app):
    """Create super admin if not exists"""
    with app.app_context():
        db_session = Session()
        try:
            super_admin = db_session.query(User).filter_by(is_super_admin=True).first()
            if not super_admin:
                username = os.getenv('SUPER_ADMIN_USER', 'admin')
                password = os.getenv('SUPER_ADMIN_PASSWORD', 'change-this-password')
                hashed_password = generate_password_hash(password)
                super_admin = User(
                    username=username,
                    password=hashed_password,
                    is_admin=True,
                    admin_level=99999,
                    is_super_admin=True,
                    is_active=True
                )
                db_session.add(super_admin)
                db_session.commit()
                logger.info(f"Super Admin created: {username}")
        except Exception as e:
            db_session.rollback()
            logger.error(f"Error creating super admin: {str(e)}")
            raise
        finally:
            db_session.close()

def check_auth(username, password):
    """Check authentication credentials"""
    db_session = Session()
    try:
        user = db_session.query(User).filter_by(username=username, is_active=True).first()
        if user and check_password_hash(user.password, password):
            user.last_login = datetime.now(pytz.UTC)
            db_session.commit()
            return True
        return False
    finally:
        db_session.close()

def authenticate():
    """Send authentication challenge"""
    return Response(
        'Authentication required',
        401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

# Decorators
def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in flask_session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def requires_auth(f):
    """Decorator to require HTTP basic auth"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def admin_required(min_level=1):
    """Decorator to require admin access with minimum level"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = flask_session.get('user_id')
            if not user_id:
                return redirect(url_for('login'))
            
            db_session = Session()
            try:
                user = db_session.query(User).get(user_id)
                if not user or not user.is_admin or user.admin_level < min_level:
                    abort(403)
                return f(*args, **kwargs)
            finally:
                db_session.close()
        return decorated_function
    return decorator

# History Management Functions
def save_to_history(video_url, video_title):
    """Save viewing history for user"""
    user_id = flask_session.get('user_id')
    if not user_id:
        logger.error("Attempted to save history without user_id in session")
        return

    db_session = Session()
    try:
        brasil_tz = pytz.timezone('America/Sao_Paulo')
        current_time = datetime.now(brasil_tz)

        if is_series(video_title):
            season, episode = extract_season_episode(video_title)
            if season is None or episode is None:
                logger.error(f"Could not extract season/episode from title: {video_title}")
                return

            series_base_title = re.sub(r'\s*-?\s*(\d+)ª?\s*Temporada.*', '', video_title).strip()
            
            existing_entry = db_session.query(ViewingHistory)\
                .filter_by(user_id=user_id, content_type='series', title=series_base_title)\
                .first()
                
            season_str = str(season)
            new_episode_data = {
                "episode": episode,
                "title": video_title,
                "url": video_url,
                "last_watched": current_time.isoformat()
            }

            if existing_entry:
                if not existing_entry.episodes:
                    existing_entry.episodes = {}
                
                if season_str not in existing_entry.episodes:
                    existing_entry.episodes[season_str] = []
                
                episode_found = False
                for i, ep in enumerate(existing_entry.episodes[season_str]):
                    if isinstance(ep, dict) and ep.get("episode") == episode:
                        existing_entry.episodes[season_str][i] = new_episode_data
                        episode_found = True
                        break
                
                if not episode_found:
                    existing_entry.episodes[season_str].append(new_episode_data)
                
                existing_entry.last_watched = current_time
                existing_entry.watch_count += 1
                
                db_session.query(ViewingHistory)\
                    .filter_by(id=existing_entry.id)\
                    .update({
                        ViewingHistory.episodes: existing_entry.episodes,
                        ViewingHistory.last_watched: current_time,
                        ViewingHistory.watch_count: ViewingHistory.watch_count + 1
                    })
            else:
                new_entry = ViewingHistory(
                    user_id=user_id,
                    content_type='series',
                    title=series_base_title,
                    episodes={season_str: [new_episode_data]},
                    last_watched=current_time,
                    watch_count=1
                )
                db_session.add(new_entry)
        else:
            existing_movie = db_session.query(ViewingHistory)\
                .filter_by(user_id=user_id, content_type='movie', url=video_url)\
                .first()
            
            if existing_movie:
                existing_movie.last_watched = current_time
                existing_movie.watch_count += 1
            else:
                new_movie = ViewingHistory(
                    user_id=user_id,
                    content_type='movie',
                    title=video_title,
                    url=video_url,
                    last_watched=current_time,
                    watch_count=1,
                    episodes=None
                )
                db_session.add(new_movie)

        db_session.commit()
        log_activity('watch', f'User watched: {video_title}', user_id=user_id)
        logger.info(f"History updated successfully: user_id={user_id}, title={video_title}")
    except SQLAlchemyError as e:
        db_session.rollback()
        logger.error(f"Database error while saving history: {str(e)}")
    finally:
        db_session.close()

def log_activity(activity_type, description, user_id=None):
    """Log user activity"""
    db_session = Session()
    try:
        new_activity = RecentActivity(
            activity_type=activity_type,
            description=description,
            user_id=user_id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string[:255]
        )
        db_session.add(new_activity)
        db_session.commit()
    except Exception as e:
        db_session.rollback()
        logger.error(f"Error logging activity: {str(e)}")
    finally:
        db_session.close()

# Content Scraping Functions
def get_content(url, max_retries=3, base_delay=2):
    """Get content from URL with retry mechanism"""
    global persistent_session
    
    # Check cache first
    cached_content = get_cached_content(url)
    if cached_content:
        logger.info(f"Using cached content for {url}")
        return BeautifulSoup(cached_content, "html.parser")
    
    ua = UserAgent()
    
    for attempt in range(max_retries):
        try:
            # Add exponential backoff delay between retries
            if attempt > 0:
                delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                logger.info(f"Waiting {delay:.2f} seconds before retry {attempt + 1}")
                time.sleep(delay)
            
            # Update User-Agent for each attempt
            persistent_session.headers.update({
                'User-Agent': ua.random,
                'X-Requested-With': 'XMLHttpRequest',
            })
            
            logger.info(f"Attempt {attempt + 1} for URL: {url}")
            response = persistent_session.get(
                url,
                allow_redirects=True,
                timeout=10,
                verify=False
            )
            
            # Log redirects
            if response.history:
                logger.info(f"Request was redirected {len(response.history)} times")
                for r in response.history:
                    logger.info(f"Redirect: {r.status_code} - {r.url}")
            
            response.raise_for_status()
            
            # Check for Cloudflare detection
            if 'cf-browser-verification' in response.text:
                logger.warning("Cloudflare detection encountered")
                if attempt == max_retries - 1:
                    logger.error("Failed to bypass Cloudflare after all retries")
                    return None
                continue
            
            content = response.text
            save_to_cache(url, content)
            return BeautifulSoup(content, "html.parser")
            
        except requests.RequestException as e:
            logger.error(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt == max_retries - 1:
                logger.error(f"All {max_retries} attempts failed for URL: {url}")
                return None
            
            # Recreate session on last 403 error
            if attempt == max_retries - 1 and hasattr(e, 'response') and e.response.status_code == 403:
                logger.info("Recreating session after 403 error")
                persistent_session = create_persistent_session()
                
        except Exception as e:
            logger.error(f"Unexpected error on attempt {attempt + 1}: {str(e)}")
            if attempt == max_retries - 1:
                return None

def get_video_options(soup):
    """Extract video options from parsed HTML"""
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
                    
                    # Get cover image
                    img_tag = thumbnail.select_one('img[data-echo]')
                    cover_image = img_tag['data-echo'] if img_tag else None
                    
                    # Add metadata
                    metadata = {
                        'title': title,
                        'link': link,
                        'cover_image': cover_image,
                        'type': 'series' if is_series(title) else 'movie'
                    }
                    
                    if metadata['type'] == 'series':
                        season, episode = extract_season_episode(title)
                        metadata.update({
                            'season': season,
                            'episode': episode
                        })
                    
                    options.append(metadata)
    return options

def get_total_pages(soup):
    """Extract total number of pages from pagination"""
    pagination = soup.select_one('ul.pagination')
    if pagination:
        # Try to find the last page number
        pages = pagination.select('li a')
        page_numbers = []
        for page in pages:
            try:
                num = int(page.text.strip())
                page_numbers.append(num)
            except ValueError:
                continue
        
        if page_numbers:
            return max(page_numbers)
    return 1

def get_video_embed(url):
    """Extract video embed URL from page"""
    try:
        soup = get_content(url)
        if not soup:
            return None
            
        # Try to find iframe with player
        iframe = soup.select_one('iframe[name="Player"]')
        if iframe and 'src' in iframe.attrs:
            embed_url = iframe['src']
            
            # Validate and clean embed URL
            parsed = urllib.parse.urlparse(embed_url)
            if not parsed.scheme:
                embed_url = f"https:{embed_url}"
            
            return embed_url
            
        logger.error(f"No player iframe found for URL: {url}")
        return None
        
    except Exception as e:
        logger.error(f"Error getting video embed for {url}: {str(e)}")
        return None

def fetch_page(url):
    """Fetch and process a single page of results"""
    soup = get_content(url)
    if soup:
        options = get_video_options(soup)
        # Filter out "Lista de Episódios"
        filtered_options = [
            option for option in options 
            if "Lista de Episódios" not in option['title']
        ]
        return filtered_options
    return []

def prefetch_pages(urls):
    """Prefetch multiple pages in parallel"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_url = {executor.submit(fetch_page, url): url for url in urls}
        results = []
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                data = future.result()
                results.extend(data)
            except Exception as e:
                logger.error(f"Error fetching {url}: {str(e)}")
        
        return results

def sort_videos(videos):
    """Sort videos by season and episode"""
    return sorted(videos, key=lambda x: (
        x.get('season', 0),
        x.get('episode', 0),
        x.get('title', '')
    ))

# Error Handlers
@app.errorhandler(400)
def bad_request(error):
    """Handle 400 Bad Request errors"""
    logger.warning(f"Bad Request: {error}")
    return jsonify({
        "error": "Bad Request",
        "message": str(error)
    }), 400

@app.errorhandler(401)
def unauthorized(error):
    """Handle 401 Unauthorized errors"""
    logger.warning(f"Unauthorized access attempt: {error}")
    return jsonify({
        "error": "Unauthorized",
        "message": "Please login to access this resource"
    }), 401

@app.errorhandler(403)
def forbidden(error):
    """Handle 403 Forbidden errors"""
    logger.warning(f"Forbidden access attempt: {error}")
    return jsonify({
        "error": "Forbidden",
        "message": "You don't have permission to access this resource"
    }), 403

@app.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found errors"""
    logger.warning(f"Resource not found: {error}")
    return jsonify({
        "error": "Not Found",
        "message": "The requested resource was not found"
    }), 404

@app.errorhandler(429)
def ratelimit_handler(error):
    """Handle 429 Too Many Requests errors"""
    logger.warning(f"Rate limit exceeded: {error}")
    return jsonify({
        "error": "Too Many Requests",
        "message": "Rate limit exceeded. Please try again later."
    }), 429

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 Internal Server Error"""
    logger.error(f"Internal Server Error: {error}")
    return jsonify({
        "error": "Internal Server Error",
        "message": "An unexpected error occurred. Please try again later."
    }), 500

# Basic Routes
@app.route('/')
@login_required
def index():
    """Main page route"""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('register.html'), 400
        
        db_session = Session()
        try:
            # Check existing user
            existing_user = db_session.query(User).filter_by(username=username).first()
            if existing_user:
                flash('Username already exists', 'error')
                return render_template('register.html'), 400
            
            # Create new user
            hashed_password = generate_password_hash(password)
            new_user = User(
                username=username,
                password=hashed_password,
                is_active=True
            )
            db_session.add(new_user)
            db_session.commit()
            
            log_activity('register', f'New user registered: {username}')
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except SQLAlchemyError as e:
            db_session.rollback()
            logger.error(f"Database error during registration: {str(e)}")
            flash('An error occurred during registration', 'error')
            return render_template('register.html'), 500
        finally:
            db_session.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html'), 400
        
        db_session = Session()
        try:
            user = db_session.query(User).filter_by(username=username, is_active=True).first()
            
            if user and check_password_hash(user.password, password):
                flask_session['user_id'] = user.id
                flask_session.permanent = True if remember else False
                
                # Update last login
                user.last_login = datetime.now(pytz.UTC)
                db_session.commit()
                
                log_activity('login', f'User login: {username}', user_id=user.id)
                return redirect(url_for('index'))
            
            flash('Invalid username or password', 'error')
            return render_template('login.html'), 401
            
        except SQLAlchemyError as e:
            logger.error(f"Database error during login: {str(e)}")
            flash('An error occurred during login', 'error')
            return render_template('login.html'), 500
        finally:
            db_session.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout route"""
    user_id = flask_session.get('user_id')
    if user_id:
        log_activity('logout', 'User logged out', user_id=user_id)
    flask_session.clear()
    return redirect(url_for('login'))

# Search and Content Routes
@app.route('/search', methods=['GET'])
@login_required
def search_videos():
    """Search videos route"""
    search_term = request.args.get('query')
    page = request.args.get('page', 1, type=int)
    
    if not search_term:
        return jsonify({"error": "Search query is required"}), 400
    
    try:
        base_url = f"https://redecanais.tw/tags/{urllib.parse.quote(search_term.lower())}/"
        if page > 1:
            base_url = f"{base_url}page-{page}/"
        
        logger.info(f"Searching: {base_url}")
        
        soup = get_content(base_url)
        if not soup:
            # Try alternative URL format
            alt_url = f"https://redecanais.tw/search?s={urllib.parse.quote(search_term.lower())}"
            if page > 1:
                alt_url += f"&page={page}"
            
            soup = get_content(alt_url)
            if not soup:
                return jsonify({"error": "Failed to load search results"}), 500
        
        total_pages = get_total_pages(soup)
        options = fetch_page(base_url)
        sorted_options = sort_videos(options)
        
        return jsonify({
            "current_page": page,
            "total_pages": total_pages,
            "videos": sorted_options
        })
        
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        return jsonify({"error": "An error occurred during search"}), 500

@app.route('/embed', methods=['GET'])
@login_required
def get_embed():
    """Get video embed URL route"""
    video_url = request.args.get('url')
    video_title = request.args.get('title')
    
    if not video_url or not video_title:
        return jsonify({"error": "URL and title are required"}), 400
    
    try:
        embed_url = get_video_embed(video_url)
        if not embed_url:
            return jsonify({"error": "Could not find video embed"}), 404
        
        save_to_history(video_url, video_title)
        
        return jsonify({"embed_url": embed_url})
        
    except Exception as e:
        logger.error(f"Error getting embed URL: {str(e)}")
        return jsonify({"error": "Failed to get video embed"}), 500

@app.route('/proxy')
@login_required
def proxy():
    """Proxy route for video content"""
    video_url = request.args.get('url')
    video_title = request.args.get('title')
    
    if not video_url:
        return jsonify({"error": "URL is required"}), 400
    
    try:
        video_embed_url = get_video_embed(video_url)
        if not video_embed_url:
            return jsonify({"error": "Could not find video embed"}), 404
        
        parsed_url = urllib.parse.urlparse(video_embed_url)
        adjusted_url = urllib.parse.urlunparse(parsed_url._replace(netloc="redecanais.tw"))
        
        if video_title:
            save_to_history(video_url, video_title)
        
        return jsonify({"embed_url": adjusted_url})
        
    except Exception as e:
        logger.error(f"Proxy error: {str(e)}")
        return jsonify({"error": "Failed to proxy video content"}), 500

# History Routes
@app.route('/history')
@login_required
def viewing_history():
    """View history page route"""
    return render_template('history.html')

@app.route('/get_history')
@login_required
def get_history():
    """Get user viewing history route"""
    user_id = flask_session.get('user_id')
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401
    
    db_session = Session()
    try:
        history = db_session.query(ViewingHistory)\
            .filter_by(user_id=user_id)\
            .order_by(ViewingHistory.last_watched.desc())\
            .all()
        
        history_data = []
        for item in history:
            entry = {
                "content_type": item.content_type,
                "title": item.title,
                "last_watched": item.last_watched.isoformat(),
                "watch_count": item.watch_count
            }
            
            if item.content_type == 'series':
                if item.episodes:
                    entry.update({
                        "seasons": len(item.episodes),
                        "total_episodes": sum(len(episodes) for episodes in item.episodes.values())
                    })
            else:
                entry["url"] = item.url
                
            history_data.append(entry)
        
        return jsonify(history_data)
        
    except SQLAlchemyError as e:
        logger.error(f"Database error getting history: {str(e)}")
        return jsonify({"error": "Failed to get viewing history"}), 500
    finally:
        db_session.close()

@app.route('/get_series_details')
@login_required
def get_series_details():
    """Get series details route"""
    user_id = flask_session.get('user_id')
    series_title = request.args.get('title')
    
    if not user_id or not series_title:
        return jsonify({"error": "Invalid parameters"}), 400
    
    db_session = Session()
    try:
        series = db_session.query(ViewingHistory)\
            .filter_by(user_id=user_id, content_type='series', title=series_title)\
            .first()
        
        if not series or not series.episodes:
            return jsonify({"error": "Series not found"}), 404
        
        episodes_data = []
        for season, episodes in series.episodes.items():
            for episode in episodes:
                episodes_data.append({
                    "season": int(season),
                    "episode": episode["episode"],
                    "title": episode["title"],
                    "url": episode["url"],
                    "last_watched": episode.get("last_watched", 
                                             series.last_watched.isoformat() 
                                             if series.last_watched else None)
                })
        
        response_data = {
            "title": series.title,
            "last_watched": series.last_watched.isoformat() if series.last_watched else None,
            "episodes": sorted(episodes_data, 
                             key=lambda x: (x["season"], x["episode"])),
            "total_episodes": len(episodes_data),
            "total_seasons": len(series.episodes),
            "watch_count": series.watch_count
        }
        
        return jsonify(response_data)
        
    except SQLAlchemyError as e:
        logger.error(f"Database error getting series details: {str(e)}")
        return jsonify({"error": "Failed to get series details"}), 500
    finally:
        db_session.close()
    
# Admin Routes
@app.route('/admin', methods=['GET', 'POST', 'DELETE'])
@requires_auth
def admin():
    """Admin dashboard route"""
    db_session = Session()
    try:
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

        # Get statistics
        entries = db_session.query(CacheEntry).all()
        total_users = db_session.query(User).count()
        total_cache_entries = db_session.query(CacheEntry).count()
        total_history_entries = db_session.query(ViewingHistory).count()
        
        # Get recent activities
        recent_activities = db_session.query(RecentActivity)\
            .order_by(RecentActivity.timestamp.desc())\
            .limit(10)\
            .all()

        # Convert timestamps to São Paulo timezone
        sao_paulo_tz = pytz.timezone('America/Sao_Paulo')
        for activity in recent_activities:
            activity.timestamp = activity.timestamp.replace(tzinfo=pytz.UTC).astimezone(sao_paulo_tz)

        return render_template('admin.html',
                            entries=entries,
                            total_users=total_users,
                            total_cache_entries=total_cache_entries,
                            total_history_entries=total_history_entries,
                            recent_activities=recent_activities)
                            
    except Exception as e:
        logger.error(f"Error in admin dashboard: {str(e)}")
        flash('An error occurred loading the admin dashboard', 'error')
        return redirect(url_for('index'))
    finally:
        db_session.close()

@app.route('/admin/add', methods=['POST'])
@requires_auth
def add_admin():
    """Add admin user route"""
    modifier_id = flask_session.get('user_id')
    target_username = request.json.get('username')
    admin_password = request.json.get('password')
    admin_level = request.json.get('admin_level', 1)

    try:
        admin_level = int(admin_level)
    except ValueError:
        return jsonify({"error": "Invalid admin level format"}), 400

    if not all([modifier_id, target_username, admin_password]):
        return jsonify({"error": "Missing required information"}), 400

    db_session = Session()
    try:
        modifier = db_session.query(User).get(modifier_id)
        target = db_session.query(User).filter_by(username=target_username).first()

        if not modifier or not target:
            return jsonify({"error": "User not found"}), 404

        if not modifier.is_admin or modifier.admin_level <= admin_level:
            return jsonify({"error": "Insufficient permissions"}), 403

        if target.is_admin:
            return jsonify({"error": "User is already an admin"}), 400

        target.is_admin = True
        target.admin_level = admin_level
        target.admin_password = generate_password_hash(admin_password)
        target.created_by = modifier.id

        db_session.commit()
        log_activity('add_admin', 
                    f'Admin added: {target.username} (Level {admin_level}) by {modifier.username}',
                    user_id=modifier.id)
        
        return jsonify({
            "message": f"{target.username} is now an admin with level {admin_level}"
        }), 200

    except Exception as e:
        db_session.rollback()
        logger.error(f"Error adding admin: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()

@app.route('/admin/clear_cache', methods=['POST'])
@requires_auth
def clear_cache():
    """Clear all cache entries route"""
    db_session = Session()
    try:
        count = db_session.query(CacheEntry).count()
        db_session.query(CacheEntry).delete()
        db_session.commit()
        log_activity('clear_cache', f'Cleared {count} cache entries')
        flash('Cache cleared successfully', 'success')
    except Exception as e:
        db_session.rollback()
        logger.error(f"Error clearing cache: {str(e)}")
        flash(f'Error clearing cache: {str(e)}', 'error')
    finally:
        db_session.close()
    return redirect(url_for('admin'))

@app.route('/admin/download_logs')
@requires_auth
def download_logs():
    """Download activity logs route"""
    tz = timezone('America/Sao_Paulo')
    db_session = Session()
    try:
        activities = db_session.query(RecentActivity)\
            .order_by(RecentActivity.timestamp.desc())\
            .all()

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'Activity Type', 'Description', 'User ID', 'IP Address'])
        
        for activity in activities:
            activity_time = activity.timestamp.astimezone(tz)
            writer.writerow([
                activity_time.strftime('%Y-%m-%d %H:%M:%S'),
                activity.activity_type,
                activity.description,
                activity.user_id,
                activity.ip_address
            ])

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                "Content-Disposition": "attachment;filename=activity_logs.csv",
                "Content-Type": "text/csv; charset=utf-8"
            }
        )
    except Exception as e:
        logger.error(f"Error downloading logs: {str(e)}")
        flash('Error downloading logs', 'error')
        return redirect(url_for('admin'))
    finally:
        db_session.close()

@app.route('/admin/users')
@requires_auth
def list_users():
    """List all users route"""
    db_session = Session()
    try:
        users = db_session.query(User).all()
        return render_template('users.html', users=users)
    except Exception as e:
        logger.error(f"Error listing users: {str(e)}")
        flash('Error loading user list', 'error')
        return redirect(url_for('admin'))
    finally:
        db_session.close()

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@requires_auth
def delete_user(user_id):
    """Delete user route"""
    db_session = Session()
    try:
        user = db_session.query(User).get(user_id)
        if user:
            if user.is_super_admin:
                flash('Cannot delete super admin', 'error')
                return redirect(url_for('list_users'))
                
            username = user.username
            db_session.delete(user)
            db_session.commit()
            log_activity('delete_user', f'User deleted: {username}')
            flash(f'User {username} deleted successfully', 'success')
        else:
            flash('User not found', 'error')
    except Exception as e:
        db_session.rollback()
        logger.error(f"Error deleting user: {str(e)}")
        flash('Error deleting user', 'error')
    finally:
        db_session.close()
    return redirect(url_for('list_users'))

@app.route('/health')
def health_check():
    """Health check route"""
    try:
        db_session = Session()
        # Test database connection
        db_session.execute('SELECT 1')
        db_session.close()
        
        # Get system stats
        total_users = db_session.query(User).count()
        total_cache = db_session.query(CacheEntry).count()
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.now(pytz.UTC).isoformat(),
            'stats': {
                'total_users': total_users,
                'cache_entries': total_cache
            }
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

# Main execution
if __name__ == "__main__":
    # Create tables and super admin
    try:
        Base.metadata.create_all(engine)
        create_super_admin(app)
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

    # Get port from environment or use default
    port = int(os.environ.get("PORT", 5000))
    
    # Run in development or production mode
    if os.environ.get("FLASK_ENV") == "development":
        app.run(host='0.0.0.0', port=port, debug=True)
    else:
        print("Running in production mode")
        from waitress import serve
        serve(app, host='0.0.0.0', port=port, threads=4)