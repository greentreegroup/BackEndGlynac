"""
Authentication module initialization.
This module provides user authentication, session management, and user management functionality.
"""

from flask import Blueprint
from .routes import auth_bp
from .user_routes import user_bp
from .session_routes import session_bp
# from .commands import seed_db_command

__all__ = [
    'User',
    'Auth',
    'AuthAttempts',
    'FailedLogin',
    'auth_bp',
    'user_bp',
    'session_bp'
]

def init_app(app):
    """Initialize the auth module with the Flask app."""
    # Register the auth blueprint
    app.register_blueprint(auth_bp, url_prefix='')
    app.register_blueprint(user_bp, url_prefix='')
    app.register_blueprint(session_bp, url_prefix='')

    # Register the CLI command
    # app.cli.add_command(seed_db_command) 