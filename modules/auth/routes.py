"""
Authentication routes module.
This module provides all the endpoints related to user authentication, including
registration, login, token management, and session management.
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timedelta
import bcrypt
from flask_restx import Resource
from ..common.database import db
from ..common.utils import generate_tokens, verify_token, format_error_response, format_success_response
from ..common.docs.base import auth_ns
from .docs.models import (
    login_model, register_model, user_model,
    token_model, session_model,
    login_success_model, login_validation_error_model, login_invalid_credentials_model, login_too_many_attempts_model,
    register_success_model, register_validation_error_model, register_exists_error_model,
    refresh_token_success_model, refresh_token_error_model,
    logout_success_model, logout_error_model,
    sessions_success_model, session_delete_success_model,
    session_unauthorized_model, session_not_found_model,
)
from .models import User, Auth, AuthAttempts, FailedLogin, Session  as UserSession  # Ensure Session is imported
from .helpers import (
    create_session, create_auth_record, record_failed_login,
    reset_auth_attempts, update_session_tokens, invalidate_session,
    get_active_sessions, revoke_all_sessions_except_current, is_ip_locked_out
)
from .utils.auth import require_auth , get_current_user
from .utils.validation import validate_register_data, validate_login_data

# Create Blueprint for auth routes
auth_bp = Blueprint('auth', __name__)

@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.expect(register_model)
    @auth_ns.response(201, 'User registered successfully', register_success_model)
    @auth_ns.response(400, 'Validation error', register_validation_error_model)
    @auth_ns.response(409, 'Email already exists', register_exists_error_model)
    def post(self):
        """Register a new user"""
        data = request.get_json()
        
        # Validate all registration data
        is_valid, field_errors, missing_fields = validate_register_data(data)
        if not is_valid:
            error_response = {
                'error': 'Validation failed',
                'details': field_errors or {},
                'missing_fields': missing_fields or [],
                'error_type': 'validation'
            }
            return format_error_response(error_response, 400)
        
        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return format_error_response({
                'error': 'Email already registered',
            }, 409)
        
        # Hash password using bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), salt)
        
        # Create new user
        new_user = User(
            email=data['email'],
            encrypted_password=hashed_password.decode('utf-8'),
            full_name=data['full_name'],
            phone=data.get('phone'),
            role=data.get('role', 'user')
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Generate tokens and create auth record
            tokens = generate_tokens(str(new_user.id))
            create_auth_record(
                user_id=new_user.id,
                provider='local',
                access_token=tokens['access_token'],
                refresh_token=tokens['refresh_token']
            )
            
            # Create session
            create_session(
                user_id=new_user.id,
                access_token=tokens['access_token'],
                refresh_token=tokens['refresh_token']
            )
            
            db.session.commit()
            
            return format_success_response({
                'user': {
                    'id': str(new_user.id),
                    'email': new_user.email,
                    'full_name': new_user.full_name,
                    'role': new_user.role
                },
                'tokens': tokens
            }, 'User registered successfully')
            
        except Exception as e:
            db.session.rollback()
            return format_error_response({
                'error': f'Registration failed: {str(e)}',
                'details': {'server': 'An unexpected error occurred. Please try again later.'},
                'missing_fields': [],
                'error_type': 'server'
            }, 400)

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model)
    @auth_ns.response(200, 'Login successful', login_success_model)
    @auth_ns.response(400, 'Validation error', login_validation_error_model)
    @auth_ns.response(401, 'Invalid credentials', login_invalid_credentials_model)
    @auth_ns.response(429, 'Too many attempts', login_too_many_attempts_model)
    def post(self):
        """Authenticate a user"""
        data = request.get_json()
        
        # Validate login data
        is_valid, field_errors, missing_fields = validate_login_data(data)
        if not is_valid:
            error_response = {
                'error': 'Validation failed',
                'details': field_errors or {},
                'missing_fields': missing_fields or []
            }
            return format_error_response(error_response, 400)
        
        user = User.query.filter_by(email=data['email']).first()
        
        # First check if user exists
        if not user:
            return format_error_response({
                'error': 'Invalid email or password',
            }, 401)
        
        # Only check for lockouts if user exists
        is_locked, remaining_time = is_ip_locked_out(user_id=user.id)
        if is_locked:
            return format_error_response({
                'error': f'Too many failed attempts. Please try again in {remaining_time}.',
            }, 429)
        
        # Verify password and record failed attempt if invalid
        if not bcrypt.checkpw(
            data['password'].encode('utf-8'),
            user.encrypted_password.encode('utf-8')
        ):
            failed_login, is_locked, remaining_time = record_failed_login(
                user_id=user.id
            )
            if is_locked:
                return format_error_response({
                    'error': f'Too many failed attempts. Please try again in {remaining_time}.',
                    'details': {},
                    'missing_fields': []
                }, 429)
            return format_error_response({
                'error': 'Invalid email or password',
                'details': {'password': 'Invalid password'},
                'missing_fields': []
            }, 401)
        
        # Reset failed attempts on successful login
        reset_auth_attempts(user_id=user.id)
        
        # Update last sign in timestamp
        user.last_sign_in_at = datetime.utcnow()
        
        # Generate new tokens and create auth record
        tokens = generate_tokens(str(user.id))
        create_auth_record(
            user_id=user.id,
            provider='local',
            access_token=tokens['access_token'],
            refresh_token=tokens['refresh_token']
        )
        
        # Create new session
        create_session(
            user_id=user.id,
            access_token=tokens['access_token'],
            refresh_token=tokens['refresh_token']
        )
        
        db.session.commit()
        
        return format_success_response({
            'user': {
                'id': str(user.id),
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role
            },
            'tokens': tokens
        }, 'Login successful')

@auth_ns.route('/refresh-token')
class RefreshToken(Resource):
    @auth_ns.expect(token_model)
    @auth_ns.response(200, 'Tokens refreshed successfully', refresh_token_success_model)
    @auth_ns.response(401, 'Invalid token', refresh_token_error_model)
    def post(self):
        """Refresh access token"""
        data = request.get_json()
        
        if 'refresh_token' not in data:
            return format_error_response('Refresh token is required')
        
        # Find the auth record with the refresh token
        auth = Auth.query.filter_by(refresh_token=data['refresh_token']).first()
        if not auth:
            return format_error_response('Invalid refresh token', 401)
        
        # Verify the refresh token
        payload = verify_token(data['refresh_token'])
        if not payload:
            return format_error_response('Invalid or expired refresh token', 401)
        
        user = User.query.get(payload['user_id'])
        if not user:
            return format_error_response('User not found', 404)
        
        # Generate new tokens
        tokens = generate_tokens(str(user.id))
        
        # Update the auth record with new tokens
        auth.access_token = tokens['access_token']
        auth.refresh_token = tokens['refresh_token']
        auth.expires_at = datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
        auth.updated_at = datetime.utcnow()
        
        # Update the session
        session = Session.query.filter_by(refresh_token=data['refresh_token']).first()
        if session:
            update_session_tokens(session, tokens['access_token'], tokens['refresh_token'])
        
        db.session.commit()
        
        return format_success_response({'tokens': tokens}, 'Tokens refreshed successfully')

@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.expect(token_model)
    @auth_ns.response(200, 'Logged out successfully', logout_success_model)
    @auth_ns.response(400, 'Missing token', logout_error_model)
    def post(self):
        """Logout user"""
        data = request.get_json()
        
        if 'refresh_token' not in data:
            return format_error_response('Refresh token is required')
        
        # Find and invalidate the auth record
        auth = Auth.query.filter_by(refresh_token=data['refresh_token']).first()
        if auth:
            auth.invalidated = True
        
        # Find and invalidate the session
        session = UserSession.query.filter_by(refresh_token=data['refresh_token']).first()
        if session:
            session.invalidated = True
            session.invalidated_at = datetime.utcnow()
        
        try:
            db.session.commit()
            return format_success_response(None, 'Logged out successfully')
        except Exception as e:
            db.session.rollback()
            return format_error_response(f'Failed to logout: {str(e)}', 400)

@auth_ns.route('/sessions')
class Sessions(Resource):
    @auth_ns.doc('get_sessions', security='Bearer')
    @auth_ns.response(200, 'Sessions retrieved successfully', sessions_success_model)
    @auth_ns.response(401, 'Unauthorized/Expired', session_unauthorized_model)
    @require_auth()
    def get(self):
        """Get all active sessions for the current user"""
        user = get_current_user()  # Use the helper function

        sessions = get_active_sessions(user.id)  # Fetch sessions for the user
        
        return format_success_response({
            'sessions': [{
                'id': str(session.id),
                'ip_address': session.ip_address,
                'user_agent': session.user_agent,
                'location': session.location,
                'created_at': session.created_at.isoformat(),
                'expires_at': session.expires_at.isoformat()
            } for session in sessions]
        }, 'Sessions retrieved successfully')


@auth_ns.route('/sessions/<session_id>')
@auth_ns.param('session_id', 'The session identifier')
class Session(Resource):
    @auth_ns.doc('delete_session', security='Bearer')
    @auth_ns.response(200, 'Session deleted successfully', session_delete_success_model)
    @auth_ns.response(401, 'Unauthorized/Expired', session_unauthorized_model)
    @auth_ns.response(404, 'Session not found', session_not_found_model)
    @require_auth()
    def delete(self, session_id):
        """Delete a specific session"""

        user = get_current_user()  # Use helper function from the decorator

        session = Session.query.get(session_id)
        if not session:
            return format_error_response({
                'error': 'Session not found',
                'error_type': 'not_found',
            }, 404)

        if session.user_id != user.id:
            return format_error_response({
                'error': 'You do not have permission to perform this action',
                'error_type': 'forbidden',
            }, 403)

        invalidate_session(session)

        return format_success_response(None, 'Session revoked successfully')


@auth_ns.route('/sessions/revoke-all')
class RevokeAllSessions(Resource):
    @auth_ns.doc('revoke_all_sessions', security='Bearer')
    @auth_ns.response(200, 'All other sessions deleted successfully', session_delete_success_model)
    @auth_ns.response(401, 'Unauthorized/Expired', session_unauthorized_model)
    @require_auth()
    def post(self):
        """Delete all sessions for the current user except the current one"""
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return format_error_response({
                'error': 'Missing or invalid authorization header',
                'error_type': 'unauthorized',
            }, 401)
        
        access_token = auth_header.split(' ')[1]
        payload = verify_token(access_token)
        if not payload:
            return format_error_response({
                'error': 'Session has expired',
                'error_type': 'expired',
            }, 401)
        
        revoke_all_sessions_except_current(payload['user_id'], access_token)
        
        return format_success_response(None, 'All other sessions deleted successfully')

@auth_ns.route('/users/me')
class UserProfile(Resource):
    @auth_ns.doc('get_user_profile', security='Bearer')
    @auth_ns.response(200, 'User profile retrieved successfully', user_model)
    @auth_ns.response(401, 'Unauthorized/Expired', session_unauthorized_model)
    @require_auth()
    def get(self):
        """Get the current user's profile"""
        
        user = get_current_user()  # Use helper function from the decorator
        
        if not user:
            return format_error_response({
                'error': 'User not found',
                'error_type': 'not_found',
            }, 404)
        
        return format_success_response({
            'user': {
                'id': str(user.id),
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role
            }
        }, 'User profile retrieved successfully')


@auth_ns.route('/users/me', methods=['PUT'])
class UpdateUserProfile(Resource):
    @auth_ns.doc('update_user_profile', security='Bearer')
    @auth_ns.response(200, 'User profile updated successfully', user_model)
    @auth_ns.response(400, 'Validation error', register_validation_error_model)
    @auth_ns.response(401, 'Unauthorized/Expired', session_unauthorized_model)
    @require_auth()
    def put(self):
        """Update the current user's profile"""
        
        user = get_current_user()  # Use helper function from the decorator
        
        if not user:
            return format_error_response({
                'error': 'User not found',
                'error_type': 'not_found',
            }, 404)
        
        data = request.get_json()
        
        # Update user profile
        user.full_name = data['full_name']
        user.phone = data.get('phone')
        
        try:
            db.session.commit()
            
            return format_success_response({
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'full_name': user.full_name,
                    'role': user.role
                }
            }, 'User profile updated successfully')
            
        except Exception as e:
            db.session.rollback()
            return format_error_response({
                'error': f'Failed to update user profile: {str(e)}',
                'details': {'server': 'An unexpected error occurred. Please try again later.'},
                'missing_fields': [],
                'error_type': 'server'
            }, 500)


