from functools import wraps
from flask import request
from ...common.utils import verify_token, format_error_response
from ..models import User

def require_auth(roles=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return format_error_response('Missing or invalid authorization header', 401)
            
            token = auth_header.split(' ')[1]
            payload = verify_token(token)
            if not payload:
                return format_error_response('Session has expired', 401)
            
            user = User.query.get(payload['user_id'])
            if not user:
                return format_error_response('User not found', 404)
            
            if roles and user.role not in roles:
                return format_error_response('Insufficient permissions', 403)
            
            return f(*args, **kwargs)
        return decorated
    return decorator

def get_current_user():
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]
    payload = verify_token(token)
    return User.query.get(payload['user_id']) 