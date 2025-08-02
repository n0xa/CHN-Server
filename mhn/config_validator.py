"""
Configuration validation for CHN Server
"""
import os
import sys
from urllib.parse import urlparse


class ConfigValidator:
    """Validates configuration settings and environment variables"""
    
    REQUIRED_SETTINGS = [
        'SECRET_KEY',
        'SUPERUSER_EMAIL', 
        'SUPERUSER_ONETIME_PASSWORD',
        'SERVER_BASE_URL',
        'SQLALCHEMY_DATABASE_URI'
    ]
    
    OPTIONAL_SETTINGS = {
        'DEBUG': bool,
        'LOG_FILE_PATH': str,
        'MONGODB_HOST': str,
        'MONGODB_PORT': int,
        'HPFEEDS_HOST': str,
        'HPFEEDS_PORT': int,
        'MAIL_SERVER': str,
        'MAIL_PORT': int,
        'MAIL_USE_TLS': bool,
        'MAIL_USE_SSL': bool,
        'MAIL_USERNAME': str,
        'MAIL_PASSWORD': str,
        'DEFAULT_MAIL_SENDER': str,
        'STRUCTURED_LOGGING': bool,
        'HONEYMAP_URL': str,
        'DEPLOY_KEY': str,
    }
    
    @classmethod
    def validate_config(cls, config_obj):
        """Validate configuration object"""
        errors = []
        warnings = []
        
        # Check required settings
        for setting in cls.REQUIRED_SETTINGS:
            value = config_obj.get(setting) if hasattr(config_obj, 'get') else getattr(config_obj, setting, None)
            if not value:
                errors.append(f"Required setting '{setting}' is missing or empty")
        
        # Validate specific settings
        secret_key = config_obj.get('SECRET_KEY') if hasattr(config_obj, 'get') else getattr(config_obj, 'SECRET_KEY', None)
        if secret_key:
            if len(secret_key) < 32:
                warnings.append("SECRET_KEY should be at least 32 characters long")
        
        url = config_obj.get('SERVER_BASE_URL') if hasattr(config_obj, 'get') else getattr(config_obj, 'SERVER_BASE_URL', None)
        if url:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                errors.append("SERVER_BASE_URL must be a valid URL")
        
        email = config_obj.get('SUPERUSER_EMAIL') if hasattr(config_obj, 'get') else getattr(config_obj, 'SUPERUSER_EMAIL', None)
        if email:
            if '@' not in email:
                errors.append("SUPERUSER_EMAIL must be a valid email address")
        
        # Validate database URI
        db_uri = config_obj.get('SQLALCHEMY_DATABASE_URI') if hasattr(config_obj, 'get') else getattr(config_obj, 'SQLALCHEMY_DATABASE_URI', None)
        if db_uri:
            if db_uri.startswith('sqlite:///'):
                # Check if directory exists for SQLite
                db_path = db_uri.replace('sqlite:///', '')
                db_dir = os.path.dirname(db_path)
                if db_dir and not os.path.exists(db_dir):
                    warnings.append(f"Database directory '{db_dir}' does not exist")
        
        # Check optional settings types
        for setting, expected_type in cls.OPTIONAL_SETTINGS.items():
            value = config_obj.get(setting) if hasattr(config_obj, 'get') else getattr(config_obj, setting, None)
            if value is not None and not isinstance(value, expected_type):
                warnings.append(f"Setting '{setting}' should be of type {expected_type.__name__}")
        
        return errors, warnings
    
    @classmethod
    def validate_environment(cls):
        """Validate environment variables"""
        warnings = []
        
        # Check for sensitive data in environment
        sensitive_patterns = ['password', 'secret', 'key', 'token']
        for key in os.environ:
            if any(pattern in key.lower() for pattern in sensitive_patterns):
                if len(os.environ[key]) < 16:
                    warnings.append(f"Environment variable '{key}' appears to contain sensitive data but is very short")
        
        # Check for development vs production settings
        if os.environ.get('FLASK_ENV') == 'development' and os.environ.get('DEBUG') != 'True':
            warnings.append("FLASK_ENV is 'development' but DEBUG is not enabled")
        
        return warnings
    
    @classmethod
    def print_validation_results(cls, errors, warnings):
        """Print validation results to console"""
        if errors:
            print("❌ Configuration Errors:", file=sys.stderr)
            for error in errors:
                print(f"  • {error}", file=sys.stderr)
            print()
        
        if warnings:
            print("⚠️  Configuration Warnings:")
            for warning in warnings:
                print(f"  • {warning}")
            print()
        
        if not errors and not warnings:
            print("✅ Configuration validation passed")
        
        return len(errors) == 0


def validate_config_file(config_path='config'):
    """Validate configuration file"""
    try:
        if isinstance(config_path, str):
            import importlib
            config_obj = importlib.import_module(config_path)
        else:
            config_obj = config_path
            
        config_errors, config_warnings = ConfigValidator.validate_config(config_obj)
        env_warnings = ConfigValidator.validate_environment()
        
        all_warnings = config_warnings + env_warnings
        
        ConfigValidator.print_validation_results(config_errors, all_warnings)
        
        return len(config_errors) == 0
        
    except ImportError as e:
        print(f"❌ Could not import config: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"❌ Configuration validation failed: {e}", file=sys.stderr)
        return False


if __name__ == '__main__':
    """Run configuration validation from command line"""
    import sys
    config_path = sys.argv[1] if len(sys.argv) > 1 else 'config'
    success = validate_config_file(config_path)
    sys.exit(0 if success else 1)