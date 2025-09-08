"""
Test authentication routes for functional testing.
These routes are only available in development environments.
"""

from flask import Blueprint, request, session, jsonify, current_app
from app.utils.tracing import trace

bp = Blueprint('test_auth', __name__, url_prefix='/test')


@bp.route('/set-session', methods=['POST'])
def set_session():
    """Set session data for testing purposes."""
    trace(current_app, 'routes.test_auth.set_session')
    data = request.get_json() or {}
    
    # Create user object in session (as expected by admin_required decorator)
    session['user'] = {
        'sub': data.get('user_id', 'test-user'),
        'email': data.get('email', 'test@example.com'),
        'name': data.get('name', 'Test User'),
        'groups': data.get('groups', ['users'])
    }
    
    current_app.logger.info(f"Test session set for user: {session['user']['sub']}")
    
    return jsonify({
        'status': 'success',
        'message': 'Session data set',
        'user_id': session['user']['sub'],
        'groups': session['user']['groups']
    })


@bp.route('/clear-session', methods=['POST'])
def clear_session():
    """Clear session data for testing purposes."""
    trace(current_app, 'routes.test_auth.clear_session')
    session.clear()
    
    return jsonify({
        'status': 'success',
        'message': 'Session cleared'
    })


@bp.route('/get-session', methods=['GET'])
def get_session():
    """Get current session data for testing purposes."""
    trace(current_app, 'routes.test_auth.get_session')
    user = session.get('user', {})
    return jsonify({
        'user_id': user.get('sub'),
        'email': user.get('email'),
        'name': user.get('name'),
        'groups': user.get('groups', [])
    })