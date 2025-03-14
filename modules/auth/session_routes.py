"""
Session management routes module.
This module provides endpoints for managing user sessions, including viewing,
monitoring, and terminating sessions with role-based access control.
"""

from flask import request
from flask_restx import Resource
from datetime import datetime
from ..common.database import db
from ..common.utils import format_error_response, format_success_response
from ..common.docs.base import session_ns
from .models import Session, AuthAttempts, FailedLogin , User
from .utils.auth import require_auth, get_current_user
from .docs.models import (
    session_model, session_list_success_model,
    session_unauthorized_model, session_forbidden_model,
    session_not_found_model, session_delete_success_model
)
from .helpers import (
    invalidate_session,
)

@session_ns.route('/')
class Sessions(Resource):
    @session_ns.doc(security='Bearer')
    @session_ns.response(200, 'Sessions retrieved successfully', session_list_success_model)
    @session_ns.response(401, 'Unauthorized', session_unauthorized_model)
    @session_ns.response(403, 'Forbidden', session_forbidden_model)
    @require_auth(roles=['admin'])
    def get(self):
        """Get all active sessions grouped by user (Admin only)"""
        sessions = (
            db.session.query(Session, User)
            .join(User, Session.user_id == User.id)
            .filter(Session.expires_at > datetime.utcnow(), Session.invalidated == False)
            .order_by(User.id, Session.created_at.desc())  # Order by user and latest session
            .all()
        )

        user_sessions_map = {}

        for session, user in sessions:
            user_id_str = str(user.id)
            
            # If user is not already in the map, initialize their entry
            if user_id_str not in user_sessions_map:
                user_sessions_map[user_id_str] = {
                    'user_id': user_id_str,
                    'user_email': user.email,
                    'user_name': user.full_name,
                    'user_role': user.role.value,
                    'phone': user.phone,
                    'account_status': user.account_status,
                    'profile_image_url': user.profile_image_url,
                    'is_sso_user': user.is_sso_user,
                    'sessions': []  # This will store all sessions for the user
                }
            
            # Add session details under the respective user
            user_sessions_map[user_id_str]['sessions'].append({
                'session_id': str(session.id),
                'ip_address': session.ip_address,
                'user_agent': session.user_agent,
                'location': session.location,
                'created_at': session.created_at.isoformat(),
                'expires_at': session.expires_at.isoformat()
            })

        return format_success_response({
            'sessions_by_user': list(user_sessions_map.values())
        }, 'Sessions retrieved successfully')



@session_ns.route('/<string:session_id>')
@session_ns.param('session_id', 'The session identifier')
class SessionResource(Resource):
    @session_ns.doc(security='Bearer')
    @session_ns.response(200, 'Session invalidated successfully', session_delete_success_model)
    @session_ns.response(401, 'Unauthorized', session_unauthorized_model)
    @session_ns.response(403, 'Forbidden', session_forbidden_model)
    @session_ns.response(404, 'Session not found', session_not_found_model)
    @require_auth(roles=['admin'])
    def delete(self, session_id):
        """Force logout by invalidating a session (Admin only)"""
        session = Session.query.get(session_id)
        if not session:
            return format_error_response('Session not found', 404)
        
        try:
            invalidate_session(session)  # Use your function to invalidate session and auth
            return format_success_response(None, 'Session invalidated successfully')
        except Exception as e:
            db.session.rollback()
            return format_error_response(f'Failed to invalidate session: {str(e)}', 400)


@session_ns.route('/me')
class MySessionsResource(Resource):
    @session_ns.doc(security='Bearer')
    @session_ns.response(200, 'Sessions retrieved successfully', session_list_success_model)
    @session_ns.response(401, 'Unauthorized', session_unauthorized_model)
    @require_auth()
    def get(self):
        """Get current user's active sessions"""
        current_user = get_current_user()
        sessions = Session.query.filter(
            Session.user_id == current_user.id,
            Session.expires_at > datetime.utcnow()
        ).all()
        
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

@session_ns.route('/me/<string:session_id>')
@session_ns.param('session_id', 'The session identifier')
class MySessionResource(Resource):
    @session_ns.doc(security='Bearer')
    @session_ns.response(200, 'Session invalidated successfully', session_delete_success_model)
    @session_ns.response(401, 'Unauthorized', session_unauthorized_model)
    @session_ns.response(403, 'Forbidden', session_forbidden_model)
    @session_ns.response(404, 'Session not found', session_not_found_model)
    @require_auth()
    def delete(self, session_id):
        """Invalidate a specific session for the current user"""
        current_user = get_current_user()
        session = Session.query.get(session_id)
        
        if not session:
            return format_error_response('Session not found', 404)
        
        if str(session.user_id) != str(current_user.id):
            return format_error_response('You do not have permission to invalidate this session', 403)
        
        try:
            invalidate_session(session)  # Use the function to mark the session as invalid
            return format_success_response(None, 'Session invalidated successfully')
        except Exception as e:
            db.session.rollback()
            return format_error_response(f'Failed to invalidate session: {str(e)}', 400)


@session_ns.route('/auth-attempts')
class AuthAttemptsResource(Resource):
    @session_ns.doc(security='Bearer')
    @session_ns.response(200, 'Auth attempts retrieved successfully')
    @session_ns.response(401, 'Unauthorized', session_unauthorized_model)
    @session_ns.response(403, 'Forbidden', session_forbidden_model)
    @require_auth(roles=['admin'])
    def get(self):
        """Get all authentication attempts (Admin only)"""
        attempts = AuthAttempts.query.all()
        return format_success_response({
            'attempts': [{
                'id': str(attempt.id),
                'user_id': str(attempt.user_id),
                'ip_address': attempt.ip_address,
                'user_agent': attempt.user_agent,
                'location': attempt.location,
                'attempt_count': attempt.attempt_count,
                'last_attempt_at': attempt.last_attempt_at.isoformat(),
                'locked_until': attempt.locked_until.isoformat() if attempt.locked_until else None
            } for attempt in attempts]
        }, 'Auth attempts retrieved successfully')

@session_ns.route('/auth-attempts/me')
class MyAuthAttemptsResource(Resource):
    @session_ns.doc(security='Bearer')
    @session_ns.response(200, 'Auth attempts retrieved successfully')
    @session_ns.response(401, 'Unauthorized', session_unauthorized_model)
    @require_auth()
    def get(self):
        """Get current user's authentication attempts"""
        current_user = get_current_user()
        attempts = AuthAttempts.query.filter_by(user_id=current_user.id).all()
        return format_success_response({
            'attempts': [{
                'ip_address': attempt.ip_address,
                'user_agent': attempt.user_agent,
                'location': attempt.location,
                'attempt_count': attempt.attempt_count,
                'last_attempt_at': attempt.last_attempt_at.isoformat(),
                'locked_until': attempt.locked_until.isoformat() if attempt.locked_until else None
            } for attempt in attempts]
        }, 'Auth attempts retrieved successfully')

@session_ns.route('/failed-logins')
class FailedLoginsResource(Resource):
    @session_ns.doc(security='Bearer')
    @session_ns.response(200, 'Failed logins retrieved successfully')
    @session_ns.response(401, 'Unauthorized', session_unauthorized_model)
    @session_ns.response(403, 'Forbidden', session_forbidden_model)
    @require_auth(roles=['admin'])
    def get(self):
        """Get all failed login attempts (Admin only)"""
        failed_logins = FailedLogin.query.all()
        return format_success_response({
            'failed_logins': [{
                'id': str(login.id),
                'user_id': str(login.user_id),
                'ip_address': login.ip_address,
                'user_agent': login.user_agent,
                'location': login.location,
                'created_at': login.created_at.isoformat()
            } for login in failed_logins]
        }, 'Failed logins retrieved successfully')

@session_ns.route('/failed-logins/me')
class MyFailedLoginsResource(Resource):
    @session_ns.doc(security='Bearer')
    @session_ns.response(200, 'Failed logins retrieved successfully')
    @session_ns.response(401, 'Unauthorized', session_unauthorized_model)
    @require_auth()
    def get(self):
        """Get current user's failed login attempts"""
        current_user = get_current_user()
        failed_logins = FailedLogin.query.filter_by(user_id=current_user.id).all()
        return format_success_response({
            'failed_logins': [{
                'ip_address': login.ip_address,
                'user_agent': login.user_agent,
                'location': login.location,
                'created_at': login.created_at.isoformat()
            } for login in failed_logins]
        }, 'Failed logins retrieved successfully') 