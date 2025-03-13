"""
Authentication module initialization.
This module provides user authentication, session management, and user management functionality.
"""

from .models import User, Auth, AuthAttempts, FailedLogin, Session

__all__ = [
    'User',
    'Auth',
    'AuthAttempts',
    'FailedLogin',
    'Session'
]

def init_app(app):
    """Initialize the auth module with the Flask app."""
    # Import routes to register them with the namespaces
    # Routes must be imported here to avoid circular imports
    from . import routes
    from . import user_routes
    from . import session_routes 