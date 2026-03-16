from flask import Blueprint, jsonify
from sqlalchemy import text

from app.extensions import db

bp = Blueprint('health', __name__)

@bp.route('/health')
def health_check():
    """Simple health check endpoint that returns 200 OK."""

    try:
        # Test database connection
        db.session.execute(text('SELECT 1'))
        
        return jsonify({
            'status': 'healthy',
            'service': 'frontend',
            'database': 'connected'
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'service': 'frontend',
            'database': 'disconnected',
            'error': str(e)
        }), 503