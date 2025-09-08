"""
Main blueprint for the versioned API.
"""

from flask import Blueprint
from app.extensions import csrf

# This is the parent blueprint for the entire API
bp = Blueprint('api', __name__, url_prefix='/api')

# Import and register the v1 blueprint
from .v1 import bp as v1_bp
bp.register_blueprint(v1_bp)

csrf.exempt(bp)