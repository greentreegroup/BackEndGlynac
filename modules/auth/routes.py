"""
Authentication routes module.
This module provides all the endpoints related to user authentication, including
registration, login, token management, and session management.
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timedelta
import bcrypt
from ..common.database import db
from ..common.utils import generate_tokens, verify_token, format_error_response, format_success_response
from .models import User, Auth, AuthAttempts, FailedLogin, Session
from .utils import (
    create_session, create_auth_record, record_failed_login,
    reset_auth_attempts, update_session_tokens, invalidate_session,
    get_active_sessions, revoke_all_sessions_except_current, is_ip_locked_out
)

# Create Blueprint for auth routes
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user.
    
    Request Body:
        email (str): User's email address
        password (str): User's password
        full_name (str): User's full name
        phone (str, optional): User's phone number
        role (str, optional): User's role (defaults to 'user')
    
    Returns:
        JSON response containing user details and authentication tokens
    """
    data = request.get_json()
    
    # Validate required fields
    if not all(k in data for k in ['email', 'password', 'full_name']):
        return format_error_response('Missing required fields')
    
    # Check if user already exists
    if User.query.filter_by(email=data['email']).first():
        return format_error_response('Email already registered')
    
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

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate a user and create a new session.
    
    Request Body:
        email (str): User's email address
        password (str): User's password
    
    Returns:
        JSON response containing user details and authentication tokens
    """
    data = request.get_json()
    
    if not all(k in data for k in ['email', 'password']):
        return format_error_response('Missing email or password')
    
    user = User.query.filter_by(email=data['email']).first()
    
    # First check if user exists
    if not user:
        return format_error_response('Invalid email or password', 401)
    
    # Only check for lockouts if user exists
    is_locked, remaining_time = is_ip_locked_out(user_id=user.id)
    if is_locked:
        return format_error_response(
            f'Too many failed attempts. Please try again in {remaining_time}.',
            429  # Too Many Requests
        )
    
    # Verify password and record failed attempt if invalid
    if not bcrypt.checkpw(
        data['password'].encode('utf-8'),
        user.encrypted_password.encode('utf-8')
    ):
        failed_login, is_locked, remaining_time = record_failed_login(
            user_id=user.id
        )
        if is_locked:
            return format_error_response(
                f'Too many failed attempts. Please try again in {remaining_time}.',
                429
            )
        return format_error_response('Invalid email or password', 401)
    
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

@auth_bp.route('/refresh-token', methods=['POST'])
def refresh_token():
    """
    Refresh the access token using a valid refresh token.
    
    Request Body:
        refresh_token (str): Valid refresh token
    
    Returns:
        JSON response containing new access and refresh tokens
    """
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

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    Logout a user by invalidating their session and auth record.
    
    Request Body:
        refresh_token (str): Refresh token to invalidate
    
    Returns:
        JSON response confirming successful logout
    """
    data = request.get_json()
    
    if 'refresh_token' not in data:
        return format_error_response('Refresh token is required')
    
    # Find and invalidate the auth record
    auth = Auth.query.filter_by(refresh_token=data['refresh_token']).first()
    if auth:
        db.session.delete(auth)
    
    # Find and invalidate the session
    session = Session.query.filter_by(refresh_token=data['refresh_token']).first()
    if session:
        invalidate_session(session)
    
    db.session.commit()
    
    return format_success_response(None, 'Logged out successfully')

@auth_bp.route('/sessions', methods=['GET'])
def get_sessions():
    """
    Get all active sessions for the current user.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Returns:
        JSON response containing list of active sessions
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return format_error_response('Missing or invalid authorization header', 401)
    
    access_token = auth_header.split(' ')[1]
    payload = verify_token(access_token)
    if not payload:
        return format_error_response('Invalid or expired access token', 401)
    
    sessions = get_active_sessions(payload['user_id'])
    
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

@auth_bp.route('/sessions/<session_id>', methods=['DELETE'])
def revoke_session(session_id):
    """
    Revoke a specific session.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Args:
        session_id: ID of the session to revoke
    
    Returns:
        JSON response confirming successful session revocation
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return format_error_response('Missing or invalid authorization header', 401)
    
    access_token = auth_header.split(' ')[1]
    payload = verify_token(access_token)
    if not payload:
        return format_error_response('Invalid or expired access token', 401)
    
    session = Session.query.get(session_id)
    if not session:
        return format_error_response('Session not found', 404)
    
    if session.user_id != payload['user_id']:
        return format_error_response('Unauthorized', 403)
    
    invalidate_session(session)
    
    return format_success_response(None, 'Session revoked successfully')

@auth_bp.route('/sessions/revoke-all', methods=['POST'])
def revoke_all_sessions():
    """
    Revoke all sessions for the current user except the current one.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Returns:
        JSON response confirming successful revocation of all other sessions
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return format_error_response('Missing or invalid authorization header', 401)
    
    access_token = auth_header.split(' ')[1]
    payload = verify_token(access_token)
    if not payload:
        return format_error_response('Invalid or expired access token', 401)
    
    revoke_all_sessions_except_current(payload['user_id'], access_token)
    
    return format_success_response(None, 'All other sessions revoked successfully')

