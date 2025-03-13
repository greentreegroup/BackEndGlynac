import jwt
from datetime import datetime, timedelta
from typing import Dict, Any
from flask import current_app

def generate_tokens(user_id: str) -> Dict[str, str]:
    """Generate access and refresh tokens for a user."""
    access_token = jwt.encode(
        {
            'user_id': user_id,
            'exp': datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
        },
        current_app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )
    
    refresh_token = jwt.encode(
        {
            'user_id': user_id,
            'exp': datetime.utcnow() + current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
        },
        current_app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )
    
    return {
        'access_token': access_token,
        'refresh_token': refresh_token
    }

def verify_token(token: str) -> Dict[str, Any]:
    """Verify a JWT token and return its payload."""
    try:
        payload = jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def format_error_response(message: str, status_code: int = 400) -> tuple:
    """Format an error response."""
    return {'error': message}, status_code

def format_success_response(data: Any, message: str = "Success") -> tuple:
    """Format a success response."""
    return {
        'message': message,
        'data': data
    }, 200 