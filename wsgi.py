"""
WSGI entry point for the Certificate Transparency Service.

This module provides the WSGI application instance for deployment
with WSGI servers like Gunicorn.
"""

import os
from app import create_app

config_name = os.getenv('ENVIRONMENT', 'development')
application = create_app(config_name)

if __name__ == '__main__':
    application.run(debug=True, host='0.0.0.0', port=8600)