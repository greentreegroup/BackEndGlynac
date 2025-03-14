"""
Utility functions for authentication module.
This module provides helper functions for managing user sessions, authentication records,
and security-related operations.
"""

from datetime import datetime, timedelta
from flask import request, current_app
from ..common.database import db
from .models import Session, Auth, AuthAttempts, FailedLogin

def create_session(user_id, access_token, refresh_token, ip_address=None, user_agent=None, location=None):
    """
    Create a new user session with the provided tokens and optional metadata.
    
    Args:
        user_id: The ID of the user creating the session
        access_token: JWT access token for the session
        refresh_token: JWT refresh token for the session
        ip_address: Optional IP address of the client (defaults to request.remote_addr)
        user_agent: Optional user agent string (defaults to request.user_agent.string)
        location: Optional location information (defaults to X-Forwarded-For header or IP)
    
    Returns:
        Session: The newly created session object
    """
    if ip_address is None:
        ip_address = request.remote_addr
    if user_agent is None:
        user_agent = request.user_agent.string
    if location is None:
        location = request.headers.get('X-Forwarded-For', ip_address)
    
    session = Session(
        user_id=user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        ip_address=ip_address,
        user_agent=user_agent,
        location=location,
        expires_at=datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
    )
    db.session.add(session)
    return session

def create_auth_record(user_id, provider, access_token, refresh_token, provider_id=None):
    """
    Create a new authentication record for a user.
    
    Args:
        user_id: The ID of the user
        provider: The authentication provider (e.g., 'local', 'google', 'facebook')
        access_token: JWT access token
        refresh_token: JWT refresh token
        provider_id: Optional provider-specific user ID
    
    Returns:
        Auth: The newly created auth record
    """
    auth = Auth(
        user_id=user_id,
        provider=provider,
        provider_id=provider_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
    )
    db.session.add(auth)
    return auth

def is_ip_locked_out(ip_address=None, user_id=None):
    """
    Check if an IP address + user ID combination is locked out based on failed login attempts.
    
    Args:
        ip_address: Optional IP address to check (defaults to request.remote_addr)
        user_id: Optional user ID to check
    
    Returns:
        tuple: (bool, str) - (is_locked, remaining_time)
            - is_locked: True if IP/user_id combination is locked out, False otherwise
            - remaining_time: Time remaining in lockout (in minutes) if locked, None if not locked
    """
    if ip_address is None:
        ip_address = request.remote_addr
    
    if not user_id:
        return False, None
    
    # Check IP + user combination lockout
    auth_attempt = AuthAttempts.query.filter_by(
        ip_address=ip_address,
        user_id=user_id
    ).first()
    
    if auth_attempt and auth_attempt.attempt_count >= current_app.config['MAX_LOGIN_ATTEMPTS']:
        # Calculate remaining lockout time
        last_attempt = auth_attempt.last_attempt_at
        lockout_end = last_attempt + timedelta(minutes=current_app.config['LOGIN_TIMEOUT_MINUTES'])
        remaining = (lockout_end - datetime.utcnow()).total_seconds() / 60
        
        if remaining > 0:
            return True, f"{int(remaining)} minutes"
        else:
            # Reset attempts if lockout period has expired
            auth_attempt.attempt_count = 0
            db.session.commit()
    
    return False, None

def record_failed_login(user_id=None, ip_address=None, user_agent=None, location=None):
    """
    Record a failed login attempt and update the attempt counter.
    If the number of failed attempts exceeds MAX_LOGIN_ATTEMPTS, the IP + user_id combination will be locked out.
    
    Args:
        user_id: Optional ID of the user who failed to login
        ip_address: Optional IP address of the failed attempt
        user_agent: Optional user agent string
        location: Optional location information
    
    Returns:
        tuple: (FailedLogin, bool, str)
            - FailedLogin: The newly created failed login record
            - bool: True if IP/user_id combination is now locked out, False otherwise
            - str: Remaining lockout time if locked, None if not locked
    """
    if ip_address is None:
        ip_address = request.remote_addr
    if user_agent is None:
        user_agent = request.user_agent.string
    if location is None:
        location = request.headers.get('X-Forwarded-For', ip_address)
    
    # Create failed login record
    failed_login = FailedLogin(
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        location=location
    )
    db.session.add(failed_login)
    
    if user_id:
        # Update or create IP + user combination auth attempts counter
        auth_attempt = AuthAttempts.query.filter_by(
            ip_address=ip_address,
            user_id=user_id
        ).first()
        
        if auth_attempt:
            auth_attempt.attempt_count += 1
            auth_attempt.last_attempt_at = datetime.utcnow()
        else:
            auth_attempt = AuthAttempts(
                user_id=user_id,
                ip_address=ip_address,
                attempt_count=1
            )
            db.session.add(auth_attempt)
        
        db.session.commit()
        
        # Check if IP + user combination is now locked out
        is_locked, remaining_time = is_ip_locked_out(ip_address, user_id)
        return failed_login, is_locked, remaining_time
    
    return failed_login, False, None

def reset_auth_attempts(ip_address=None, user_id=None):
    """
    Reset the failed login attempts counter for an IP + user ID combination.
    
    Args:
        ip_address: Optional IP address to reset attempts for (defaults to request.remote_addr)
        user_id: Optional user ID to reset attempts for
    """
    if ip_address is None:
        ip_address = request.remote_addr
    
    if user_id:
        # Reset IP + user combination attempts
        auth_attempt = AuthAttempts.query.filter_by(
            ip_address=ip_address,
            user_id=user_id
        ).first()
        
        if auth_attempt:
            auth_attempt.attempt_count = 0
            db.session.commit()

def update_session_tokens(session, access_token, refresh_token):
    """
    Update the tokens for an existing session.
    
    Args:
        session: The session object to update
        access_token: New JWT access token
        refresh_token: New JWT refresh token
    """
    session.access_token = access_token
    session.refresh_token = refresh_token
    session.expires_at = datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
    session.updated_at = datetime.utcnow()
    db.session.commit()

def invalidate_session(session):
    """
    Mark a session and its associated auth token as invalidated.
    
    Args:
        session: The session object to invalidate
    """
    session.invalidated = True
    session.invalidated_at = datetime.utcnow()

    # Invalidate associated Auth token
    auth = Auth.query.filter_by(user_id=session.user_id, access_token=session.access_token).first()
    if auth:
        auth.invalidated = True
        auth.invalidated_at = datetime.utcnow()

    db.session.commit()

def get_active_sessions(user_id):
    """
    Get all active (non-invalidated) sessions for a user.
    
    Args:
        user_id: The ID of the user
    
    Returns:
        list: List of active Session objects
    """
    return Session.query.filter_by(
        user_id=user_id,
        invalidated=False
    ).order_by(Session.created_at.desc()).all()

def revoke_all_sessions_except_current(user_id, current_access_token):
    """
    Revoke all sessions for a user except the current one.
    
    Args:
        user_id: The ID of the user
        current_access_token: The access token of the current session to preserve
    """
    Session.query.filter_by(
        user_id=user_id,
        invalidated=False
    ).filter(
        Session.access_token != current_access_token
    ).update({
        'invalidated': True,
        'invalidated_at': datetime.utcnow()
    })
    db.session.commit() 