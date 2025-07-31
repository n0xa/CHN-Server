from urllib.parse import urljoin

from flask import Flask, request, jsonify, abort, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore
from flask_security.utils import hash_password as hash
from flask_mail import Mail
from werkzeug.datastructures import ETags
from xml.etree.ElementTree import Element, SubElement, tostring
from datetime import datetime
import xml.dom.minidom
import xmltodict
import uuid
import random
import string
from flask_wtf.csrf import CsrfProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_smorest import Api
import os
import re

csrf = CsrfProtect()
limiter = Limiter(key_func=get_remote_address)
talisman = Talisman()
api_docs = Api()


class AtomFeed:
    """Modern replacement for werkzeug.contrib.atom.AtomFeed"""
    
    def __init__(self, title, feed_url=None, url=None, subtitle=None, id=None):
        self.title = title
        self.feed_url = feed_url
        self.url = url
        self.subtitle = subtitle
        self.id = id or feed_url
        self.entries = []
        
    def add(self, title, content, content_type='text', author=None, 
            url=None, updated=None, published=None, id=None):
        entry = {
            'title': title,
            'content': content,
            'content_type': content_type,
            'author': author,
            'url': url,
            'updated': updated or datetime.utcnow(),
            'published': published or datetime.utcnow(),
            'id': id or url
        }
        self.entries.append(entry)
        
    def to_string(self):
        """Generate XML string for the feed"""
        feed = Element('feed', xmlns='http://www.w3.org/2005/Atom')
        
        title_elem = SubElement(feed, 'title')
        title_elem.text = self.title
        
        if self.feed_url:
            link_elem = SubElement(feed, 'link', href=self.feed_url, rel='self')
            
        if self.url:
            link_elem = SubElement(feed, 'link', href=self.url)
            
        id_elem = SubElement(feed, 'id')
        id_elem.text = self.id
        
        updated_elem = SubElement(feed, 'updated')
        updated_elem.text = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        
        for entry_data in self.entries:
            entry = SubElement(feed, 'entry')
            
            entry_title = SubElement(entry, 'title')
            entry_title.text = entry_data['title']
            
            if entry_data['id']:
                entry_id = SubElement(entry, 'id')
                entry_id.text = str(entry_data['id'])
                
            if entry_data['url']:
                entry_link = SubElement(entry, 'link', href=entry_data['url'])
                
            entry_updated = SubElement(entry, 'updated')
            entry_updated.text = entry_data['updated'].strftime('%Y-%m-%dT%H:%M:%SZ')
            
            entry_published = SubElement(entry, 'published')
            entry_published.text = entry_data['published'].strftime('%Y-%m-%dT%H:%M:%SZ')
            
            entry_content = SubElement(entry, 'content', type=entry_data['content_type'])
            entry_content.text = entry_data['content']
            
        # Pretty format the XML
        rough_string = tostring(feed, 'utf-8')
        reparsed = xml.dom.minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ", encoding='utf-8').decode('utf-8')
        
    def get_response(self):
        """Return Flask response with proper headers"""
        from flask import Response
        return Response(
            self.to_string(),
            mimetype='application/atom+xml',
            headers={'Content-Type': 'application/atom+xml; charset=utf-8'}
        )

# Initialize extensions
db = SQLAlchemy()
mail = Mail()
security = Security()

# Global variables for compatibility
user_datastore = None
mhn = None


def create_app(config_object='config'):
    """Application factory pattern for Flask app creation"""
    global user_datastore, mhn
    
    app = Flask(__name__)
    app.config.from_object(config_object)
    
    # Validate configuration
    if not app.config.get('TESTING', False):
        from mhn.config_validator import ConfigValidator
        errors, warnings = ConfigValidator.validate_config(app.config)
        if errors:
            app.logger.error("Configuration validation failed:")
            for error in errors:
                app.logger.error(f"  • {error}")
            raise RuntimeError("Invalid configuration. Check logs for details.")
        if warnings:
            for warning in warnings:
                app.logger.warning(f"Config warning: {warning}")
    
    # Initialize extensions with app
    csrf.init_app(app)
    mail.init_app(app)
    db.init_app(app)
    
    # Initialize security extensions
    limiter.init_app(app)
    
    # Configure Talisman security headers (adjust for honeypot functionality)
    talisman.init_app(app, 
        force_https=False,  # Honeypots often run on HTTP
        strict_transport_security=False,
        content_security_policy={
            'default-src': "'self'",
            'script-src': "'self' 'unsafe-inline' https://kozea.github.io",
            'style-src': "'self' 'unsafe-inline'",
            'img-src': "'self' data:",
        }
    )
    
    # Initialize API documentation
    app.config.setdefault('API_TITLE', 'CHN Server API')
    app.config.setdefault('API_VERSION', 'v2.0')
    app.config.setdefault('OPENAPI_VERSION', '3.0.2')
    app.config.setdefault('OPENAPI_URL_PREFIX', '/api/docs')
    app.config.setdefault('OPENAPI_SWAGGER_UI_PATH', '/swagger')
    app.config.setdefault('OPENAPI_SWAGGER_UI_URL', 'https://cdn.jsdelivr.net/npm/swagger-ui-dist/')
    
    api_docs.init_app(app)
    
    # Import models after db is configured
    from mhn.auth.models import User, Role, ApiKey
    
    # Setup user datastore and security
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    
    # Configure Flask-Security for version 5.x
    app.config.setdefault('SECURITY_PASSWORD_HASH', 'bcrypt')
    app.config.setdefault('SECURITY_PASSWORD_SINGLE_HASH', ['bcrypt', 'argon2', 'pbkdf2_sha256'])
    app.config.setdefault('SECURITY_DEPRECATED_PASSWORD_SCHEMES', ['sha512_crypt'])
    app.config.setdefault('SECURITY_LOGIN_URL', '/ui/login/')
    app.config.setdefault('SECURITY_LOGOUT_URL', '/ui/logout/')
    app.config.setdefault('SECURITY_POST_LOGIN_REDIRECT_URL', '/ui/')
    app.config.setdefault('SECURITY_POST_LOGOUT_REDIRECT_URL', '/ui/login/')
    app.config.setdefault('SECURITY_REGISTERABLE', False)  # Disable registration for security
    app.config.setdefault('SECURITY_RECOVERABLE', True)
    app.config.setdefault('SECURITY_TRACKABLE', True)
    app.config.setdefault('SECURITY_CHANGEABLE', True)
    app.config.setdefault('SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS', True)
    
    security.init_app(app, user_datastore)
    
    # Register blueprints
    from mhn.api.views import api
    app.register_blueprint(api)
    
    from mhn.ui.views import ui
    app.register_blueprint(ui)
    
    from mhn.auth.views import auth
    app.register_blueprint(auth)
    
    # Setup template filters and context processors
    from mhn.common.templatetags import format_date
    app.jinja_env.filters['fdate'] = format_date
    
    from mhn.auth.contextprocessors import user_ctx
    app.context_processor(user_ctx)
    
    from mhn.common.contextprocessors import config_ctx
    app.context_processor(config_ctx)
    
    # Setup error handlers
    setup_error_handlers(app)
    
    # Setup logging
    setup_logging(app)
    
    # Add feed routes
    app.add_url_rule('/feed.json', 'json_feed', lambda: json_feed(app))
    app.add_url_rule('/feed.xml', 'xml_feed', lambda: xml_feed(app))
    
    # Set global reference for backward compatibility
    mhn = app
    
    return app


def setup_error_handlers(app):
    """Configure modern error handlers"""
    from flask import jsonify, render_template
    
    @app.errorhandler(400)
    def bad_request(error):
        if request.content_type == 'application/json':
            return jsonify({'error': 'Bad request'}), 400
        return render_template('errors/400.html'), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        if request.content_type == 'application/json':
            return jsonify({'error': 'Unauthorized'}), 401
        return render_template('errors/401.html'), 401
        
    @app.errorhandler(403)
    def forbidden(error):
        if request.content_type == 'application/json':
            return jsonify({'error': 'Forbidden'}), 403
        return render_template('errors/403.html'), 403
    
    @app.errorhandler(404)
    def not_found(error):
        if request.content_type == 'application/json':
            return jsonify({'error': 'Not found'}), 404
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f'Server Error: {error}')
        if request.content_type == 'application/json':
            return jsonify({'error': 'Internal server error'}), 500
        return render_template('errors/500.html'), 500


def setup_logging(app):
    """Configure structured application logging"""
    import logging
    import json
    from logging.handlers import RotatingFileHandler
    
    class StructuredFormatter(logging.Formatter):
        """JSON structured log formatter"""
        def format(self, record):
            log_entry = {
                'timestamp': self.formatTime(record),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno
            }
            
            # Add request context if available
            try:
                from flask import request, g
                if request:
                    log_entry.update({
                        'request_id': getattr(g, 'request_id', None),
                        'remote_addr': request.remote_addr,
                        'method': request.method,
                        'url': request.url,
                        'user_agent': request.headers.get('User-Agent')
                    })
            except:
                pass
                
            return json.dumps(log_entry)
    
    app.logger.setLevel(logging.INFO)
    
    # Use JSON formatter for structured logging
    if app.config.get('STRUCTURED_LOGGING', True):
        formatter = StructuredFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    if 'LOG_FILE_PATH' in app.config:
        handler = RotatingFileHandler(
            app.config['LOG_FILE_PATH'], maxBytes=10240000, backupCount=5, encoding='utf8')
        handler.setLevel(logging.INFO)
        handler.setFormatter(formatter)
        app.logger.addHandler(handler)
        
    if app.config.get('DEBUG'):
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(formatter)
        app.logger.addHandler(console)
        
    # Add request ID middleware
    @app.before_request
    def add_request_id():
        import uuid
        from flask import g
        g.request_id = str(uuid.uuid4())[:8]


def json_feed(app=None):
    """JSON feed endpoint"""
    if app is None:
        app = mhn
    with app.app_context():
        feed_content = get_feed(app).to_string()
        return jsonify(xmltodict.parse(feed_content))


def xml_feed(app=None):
    """XML feed endpoint"""
    if app is None:
        app = mhn
    with app.app_context():
        return get_feed(app).get_response()


# Create default app instance for backward compatibility
mhn = create_app()


def makeurl(uri, app=None):
    """Generate URL with base URL from config"""
    if app is None:
        app = mhn
    baseurl = app.config['SERVER_BASE_URL']
    return urljoin(baseurl, uri)


def get_feed(app=None):
    """Generate Atom feed for honeypot sessions"""
    if app is None:
        app = mhn
        
    from mhn.common.clio import Clio
    from mhn.auth import current_user
    
    authfeed = app.config['FEED_AUTH_REQUIRED']
    if authfeed and not current_user.is_authenticated:
        abort(404)
        
    feed = AtomFeed('MHN HpFeeds Report', feed_url=request.url,
                    url=request.url_root)
    sessions = Clio().session.get(options={'limit': 1000})
    for s in sessions:
        feedtext = u'Sensor "{identifier}" '
        feedtext += '{source_ip}:{source_port} on sensorip:{destination_port}.'
        feedtext = feedtext.format(**s.to_dict())
        feed.add('Feed', feedtext, content_type='text',
                 published=s.timestamp, updated=s.timestamp,
                 url=makeurl(url_for('api.get_session', session_id=str(s._id)), app))
    return feed


def create_clean_db():
    """
    Use from a python shell to create a fresh database.
    """
    with mhn.test_request_context():
        db.create_all()
        superuser = create_superuser_entry()

        from mhn.api.models import DeployScript
        # Creating a initial deploy scripts.
        deployscripts = {
            'Default - Conpot': os.path.abspath('./scripts/deploy_conpot.sh'),
            'Default - Dionaea': os.path.abspath('./scripts/deploy_dionaea.sh'),
            'Default - Cowrie': os.path.abspath('./scripts/deploy_cowrie.sh'),
            'Default - RDPHoney': os.path.abspath('./scripts/deploy_rdphoney.sh'),
            'Default - UHP': os.path.abspath('./scripts/deploy_uhp.sh'),
            'Default - Elasticpot': os.path.abspath('./scripts/deploy_elasticpot.sh'),
            'Default - BigHP': os.path.abspath('./scripts/deploy_big-hp.sh'),
            'Default - ssh-auth-logger': os.path.abspath('./scripts/deploy_ssh-auth-logger.sh'),
            'Default - Honeydb-Agent': os.path.abspath('./scripts/deploy_honeydb-agent.sh')
        }
        for honeypot, deploypath in sorted(deployscripts.items()):
            with open(deploypath, 'r') as deployfile:
                initdeploy = DeployScript()
                initdeploy.script = deployfile.read()
                initdeploy.notes = 'Initial deploy script for {}'.format(honeypot)
                initdeploy.user = superuser
                initdeploy.name = honeypot
                db.session.add(initdeploy)

        db.session.commit()


def create_superuser_entry():
    # Creating superuser entry.
    superuser = user_datastore.create_user(
        email=mhn.config.get('SUPERUSER_EMAIL'),
        password=hash(mhn.config.get('SUPERUSER_ONETIME_PASSWORD')))
    adminrole = user_datastore.create_role(name='admin', description='')
    user_datastore.add_role_to_user(superuser, adminrole)
    user_datastore.create_role(name='user', description='')
    db.session.flush()

    apikey = ApiKey(user_id=superuser.id, api_key=str(uuid.uuid4()).replace("-", ""))
    db.session.add(apikey)
    db.session.flush()

    return superuser


def pretty_name(name):
    # remove trailing suffix
    nosuffix = os.path.splitext(name)[0]

    # remove special characters
    nospecial = re.sub('[\'";&%#@!()*]*', '', nosuffix)

    # Convert underscore to space
    underspace = re.sub('_', ' ', nospecial)

    return underspace


def reload_scripts():
    from mhn.api.models import DeployScript

    superuser = user_datastore.get_user(mhn.config.get('SUPERUSER_EMAIL'))
    custom_path = './custom_scripts/'

    deployscripts = {
        'Default - Conpot': os.path.abspath('./scripts/deploy_conpot.sh'),
        'Default - Dionaea': os.path.abspath('./scripts/deploy_dionaea.sh'),
        'Default - Cowrie': os.path.abspath('./scripts/deploy_cowrie.sh'),
        'Default - RDPHoney': os.path.abspath('./scripts/deploy_rdphoney.sh'),
        'Default - UHP': os.path.abspath('./scripts/deploy_uhp.sh'),
        'Default - Elasticpot': os.path.abspath('./scripts/deploy_elasticpot.sh'),
        'Default - BigHP': os.path.abspath('./scripts/deploy_big-hp.sh'),
        'Default - ssh-auth-logger': os.path.abspath('./scripts/deploy_ssh-auth-logger.sh'),
        'Default - Honeydb-Agent': os.path.abspath('./scripts/deploy_honeydb-agent.sh')
    }

    f = []
    for (dirpath, dirnames, filenames) in os.walk(custom_path):
        f.extend(filenames)
        break
    for fname in f:
        p = os.path.abspath(custom_path + fname)
        if os.path.isfile(p):
            n = pretty_name(os.path.basename(p))
            deployscripts[n] = p

    db.session.query(DeployScript).delete()
    for honeypot, deploypath in sorted(deployscripts.items()):
        with open(deploypath, 'r') as deployfile:
            initdeploy = DeployScript()
            initdeploy.script = deployfile.read()
            initdeploy.notes = 'Vanilla deploy script for {}'.format(honeypot)
            initdeploy.user = superuser
            initdeploy.name = honeypot
            db.session.add(initdeploy)
            db.session.commit()
