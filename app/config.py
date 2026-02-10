import os
import yaml
from datetime import timedelta

from app.utils.environment import loadConfigValueFromFileOrEnvironment, loadBoolConfigValue

class Config:
    """
    Base configuration
    """
    
    def __init__(self):
        self.DEBUG = False
        self.TRACE = False
        self.ENVIRONMENT = os.environ.get('ENVIRONMENT', 'production')
        self.SITE_NAME = os.environ.get('SITE_NAME', 'VPN Service')

        # Encryption Keys - These are required and must be set securely
        self.SECRET_KEY = loadConfigValueFromFileOrEnvironment('FLASK_SECRET_KEY')
        self.ENCRYPTION_KEY = loadConfigValueFromFileOrEnvironment('FERNET_ENCRYPTION_KEY')
        
        # Validate critical security keys are set
        if not self.SECRET_KEY:
            raise RuntimeError(
                "FLASK_SECRET_KEY must be set. Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )
        if not self.ENCRYPTION_KEY:
            raise RuntimeError(
                "FERNET_ENCRYPTION_KEY must be set. Generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        self.OPENVPN_TLS_CRYPT_KEY = loadConfigValueFromFileOrEnvironment('OPENVPN_TLS_CRYPT_KEY')

        # Redis/Valkey Configuration for Rate Limit configuration
        self.RATELIMIT_STORAGE_URI = loadConfigValueFromFileOrEnvironment('RATELIMIT_STORAGE_URL', 'memory://')

        # Database Configuration Values
        self.DATABASE_TYPE = os.environ.get('DATABASE_TYPE', '')
        self.DATABASE_HOSTNAME = os.environ.get('DATABASE_HOSTNAME', '')
        self.DATABASE_USERNAME = loadConfigValueFromFileOrEnvironment('DATABASE_USERNAME', '')
        self.DATABASE_PASSWORD = loadConfigValueFromFileOrEnvironment('DATABASE_PASSWORD', '')
        self.DATABASE_NAME = os.environ.get('DATABASE_NAME', '')
        self.DATABASE_PORT = os.environ.get('DATABASE_PORT', '')
        if self.DATABASE_TYPE != '' and self.DATABASE_HOSTNAME != '' and self.DATABASE_USERNAME != '' and self.DATABASE_PASSWORD != '' and self.DATABASE_NAME != '':
            if self.DATABASE_PORT != '':
                self.SQLALCHEMY_DATABASE_URI = f'{self.DATABASE_TYPE}://{self.DATABASE_USERNAME}:{self.DATABASE_PASSWORD}@{self.DATABASE_HOSTNAME}:{self.DATABASE_PORT}/{self.DATABASE_NAME}'
            else:
                self.SQLALCHEMY_DATABASE_URI = f'{self.DATABASE_TYPE}://{self.DATABASE_USERNAME}:{self.DATABASE_PASSWORD}@{self.DATABASE_HOSTNAME}/{self.DATABASE_NAME}'
        else:
            self.SQLALCHEMY_DATABASE_URI = 'sqlite:////data/sqlite/frontend.db'
        self.SQLALCHEMY_DATABASE_URI = loadConfigValueFromFileOrEnvironment('DATABASE_URL', self.SQLALCHEMY_DATABASE_URI)
        self.SQLALCHEMY_TRACK_MODIFICATIONS = loadBoolConfigValue('TRACK_MODIFICATIONS', 'false')

        # HTTPS / TLS
        self.FORCE_HTTPS = loadBoolConfigValue('FORCE_HTTPS', 'true')

        # Session settings
        self.SESSION_TYPE = 'sqlalchemy'
        self.SESSION_PERMANENT = True
        self.PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

        # OIDC settings
        self.OIDC_ADMIN_GROUP = os.environ.get('OIDC_ADMIN_GROUP', 'admins')
        self.OIDC_AUDITOR_GROUP = os.environ.get('OIDC_AUDITOR_GROUP', 'auditors')
        self.OIDC_SYSTEM_ADMIN_GROUP = os.environ.get('OIDC_SYSTEM_ADMIN_GROUP', 'system-admins')
        self.OIDC_DISCOVERY_URL = os.environ.get('OIDC_DISCOVERY_URL', '')
        self.OIDC_SCOPES = os.environ.get('OIDC_SCOPES', 'openid email profile groups')
        self.OIDC_CLIENT_ID = loadConfigValueFromFileOrEnvironment('OIDC_CLIENT_ID', '')
        self.OIDC_CLIENT_SECRET = loadConfigValueFromFileOrEnvironment('OIDC_CLIENT_SECRET', '')
        self.OIDC_DISABLE_IDP_LOGOUT_FLOW = loadBoolConfigValue('OIDC_DISABLE_IDP_LOGOUT_FLOW', 'false')
        self.OIDC_REQUIRE_PKCE = loadBoolConfigValue('OIDC_REQUIRE_PKCE', 'false')

        # Service Separation Configuration
        self.ADMIN_URL_BASE = os.environ.get('ADMIN_URL_BASE', '')
        self.USER_URL_BASE = os.environ.get('USER_URL_BASE', '')
        
        # Validate service separation configuration
        if self.ADMIN_URL_BASE and self.USER_URL_BASE:
            raise RuntimeError(
                "Configuration error: Both ADMIN_URL_BASE and USER_URL_BASE are configured. "
                "Each service deployment should configure only one URL base:\n"
                "- User service: configure ADMIN_URL_BASE (points to admin service)\n"
                "- Admin service: configure USER_URL_BASE (points to user service)\n"
                "- Combined service: configure neither (default behavior)"
            )

        # 
        self.CA_COUNTRY_NAME = os.environ.get('CA_COUNTRY_NAME', 'GB')
        self.CA_STATE_OR_PROVINCE_NAME = os.environ.get('CA_STATE_OR_PROVINCE_NAME', 'England')
        self.CA_LOCALITY_NAME = os.environ.get('CA_LOCALITY_NAME', 'London')
        self.CA_ORGANIZATION_NAME = os.environ.get('CA_ORGANIZATION_NAME', self.SITE_NAME)

        # Path for the public Root CA certificate
        self.ROOT_CA_CERTIFICATE = loadConfigValueFromFileOrEnvironment('ROOT_CA_CERTIFICATE', '')
        self.INTERMEDIATE_CA_CERTIFICATE = loadConfigValueFromFileOrEnvironment('INTERMEDIATE_CA_CERTIFICATE', '')

        # OpenVPN Server Configuration

        # Signing Service (for TLS Certificates)
        self.SIGNING_SERVICE_URL = os.environ.get('SIGNING_SERVICE_URL', 'http://localhost:5001')
        self.SIGNING_SERVICE_API_SECRET = loadConfigValueFromFileOrEnvironment('SIGNING_SERVICE_API_SECRET')

        # Certificate Transparency Service
        self.CERTTRANSPARENCY_SERVICE_URL = os.environ.get('CERTTRANSPARENCY_SERVICE_URL', 'http://certtransparency:8400')

        # Inter-service TLS validation
        self.SIGNING_SERVICE_URL_TLS_VALIDATE = loadBoolConfigValue('SIGNING_SERVICE_URL_TLS_VALIDATE', 'true')
        self.CERTTRANSPARENCY_SERVICE_URL_TLS_VALIDATE = loadBoolConfigValue('CERTTRANSPARENCY_SERVICE_URL_TLS_VALIDATE', 'true')

        # Templates and Options for Templates
        self.TEMPLATE_COLLECTION = None
        self.OVPN_TEMPLATE_PATH = os.environ.get('OVPN_TEMPLATE_PATH', './openvpn_templates')
        self.SERVER_TEMPLATES_DIR = os.environ.get('SERVER_TEMPLATES_DIR', './settings/server_templates')  # Separate directory for server templates
        self.OVPN_OPTIONS = {}
        self.OVPN_OPTIONS_PATH = os.environ.get('OVPN_OPTIONS_PATH')
        if self.OVPN_OPTIONS_PATH:
            try:
                with open(self.OVPN_OPTIONS_PATH, 'r') as f:
                    self.OVPN_OPTIONS = yaml.safe_load(f)
            except (FileNotFoundError, yaml.YAMLError):
                # Log this event in a real app
                pass

class DevelopmentConfig(Config):
    """
    Development overrides
    """
    
    def __init__(self):
        super().__init__()
        self.DEBUG = True
        self.TRACE = loadBoolConfigValue('TRACE', 'false')

        # Explicitly set development mode indicators for CLI commands
        self.ENVIRONMENT = 'development'
        self.FLASK_ENV = 'development'
        self.FLASK_CONFIG = 'development'
        
        # Database configuration priority:
        # 1. If TESTING is explicitly set (in tests), use memory database
        # 2. If DEV_DATABASE_URI is set (development/smoke tests), use it  
        # 3. If DATABASE_URL is set, use it
        # 4. Otherwise, inherit the base Config class logic
        if os.environ.get('TESTING') == 'True': # pragma: no cover
            ## PRAGMA-NO-COVER Exception; JS 2025-09-18 Actually only needed for test suite
            
            self.SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
        else: # pragma: no cover
            ## PRAGMA-NO-COVER Exception; JS 2025-09-18 Actually only needed for test suite

            DEV_DATABASE_URI = os.environ.get('DEV_DATABASE_URI', '')
            if DEV_DATABASE_URI:
                self.SQLALCHEMY_DATABASE_URI = DEV_DATABASE_URI
            elif not os.environ.get('DATABASE_TYPE') and not os.environ.get('DATABASE_URL'):
                # No database config found, use in-memory SQLite for testing
                self.SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
            # Otherwise, the base Config class logic will be used
        
        self.SQLALCHEMY_TRACK_MODIFICATIONS = True

