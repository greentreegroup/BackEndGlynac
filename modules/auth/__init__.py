from .models import User, Auth, AuthAttempts, FailedLogin
from .routes import auth_bp
from .commands import seed_db_command

__all__ = [
    'User',
    'Auth',
    'AuthAttempts',
    'FailedLogin',
    'auth_bp'
]

def init_app(app):
    """Initialize the auth module with the Flask app."""
    app.register_blueprint(auth_bp, url_prefix='')
    app.cli.add_command(seed_db_command) 