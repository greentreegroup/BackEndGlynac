from functools import wraps
from flask import request
from ...common.utils import verify_token, format_error_response
from ..models import User, Auth

def require_auth(roles=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return format_error_response({"error": "Missing or invalid authorization header", "errorType": "unauthorized"}, 401)
            
            token = auth_header.split(' ')[1]
            payload = verify_token(token)
            if not payload:
                return format_error_response({"error": "Session has expired", "errorType": "unauthorized"}, 401)
            
            user = User.query.get(payload.get('user_id'))
            if not user:
                return format_error_response({"error": "User not found", "errorType": "not_found"}, 404)
            
            # Check if the token is invalidated in Auth
            auth = Auth.query.filter_by(access_token=token).first()
            if auth and auth.invalidated:
                return format_error_response({"error": "Token has been invalidated", "errorType": "unauthorized"}, 401)
            
            if roles and user.role not in roles:
                return format_error_response({"error": "You do not have permission to perform this action", "errorType": "forbidden"}, 403)
            
            return f(*args, **kwargs)
        return decorated
    return decorator

def get_current_user():
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]
    payload = verify_token(token)
    return User.query.get(payload['user_id'])