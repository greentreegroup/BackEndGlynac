"""
User management routes module.
This module provides endpoints for user management, including creating, updating,
and viewing user profiles with role-based access control.
"""

from flask import request
from flask_restx import Resource
from datetime import datetime
import bcrypt
from ..common.database import db
from ..common.utils import format_error_response, format_success_response
from ..common.docs.base import user_ns
from .models import User, Session, Auth  # Add these imports
from .utils.auth import require_auth, get_current_user
from .utils.validation import validate_user_data
from .docs.models import (
    user_model, user_create_model, user_update_model,
    user_retrieval_success_model,
    user_success_model, user_list_success_model,
    user_update_validation_error_model, user_validation_error_model,
    user_not_found_model,user_unauthorized_model, user_forbidden_model,
    profile_update_model
)

@user_ns.route('/')
class Users(Resource):
    @user_ns.doc(security='Bearer')
    @user_ns.response(200, 'Users retrieved successfully', user_list_success_model)
    @user_ns.response(401, 'Unauthorized', user_unauthorized_model) 
    @user_ns.response(403, 'Forbidden', user_forbidden_model)
    @require_auth(roles=['admin'])
    def get(self):
        """Get all users (Admin only)"""
        users = User.query.filter_by().all()
        return format_success_response({
            'users': [{
                'id': str(user.id),
                'email': user.email,
                'full_name': user.full_name,
                'phone': user.phone,
                'role': user.role,
                'is_deleted': user.is_deleted,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_sign_in_at': user.last_sign_in_at.isoformat() if user.last_sign_in_at else None
            } for user in users]
        }, 'Users retrieved successfully')

    @user_ns.doc(security='Bearer')
    @user_ns.expect(user_create_model)
    @user_ns.response(201, 'User created successfully', user_success_model)
    @user_ns.response(400, 'Validation error', user_validation_error_model)
    @user_ns.response(401, 'Unauthorized', user_unauthorized_model)
    @user_ns.response(403, 'Forbidden', user_forbidden_model)
    @require_auth(roles=['admin'])
    def post(self):
        """Create a new user (Admin only)"""
        data = request.get_json()
        
        # Validate user data
        is_valid, field_errors, missing_fields = validate_user_data(data)
        if not is_valid:
            return format_error_response({
                'error': 'Validation failed',
                'details': field_errors,
                'missing_fields': missing_fields,
                'error_type': 'validation'
            }, 400)
        
        # Check if email already exists
        if User.query.filter_by(email=data['email']).first():
            return format_error_response({
                'error': 'Email already registered',
            }, 409)
        
        # Hash password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), salt)
        
        # Create new user
        new_user = User(
            email=data['email'],
            encrypted_password=hashed_password.decode('utf-8'),
            full_name=data['full_name'],
            phone=data.get('phone'),
            role=data.get('role', 'client')
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            return format_success_response({
                'user': {
                    'id': str(new_user.id),
                    'email': new_user.email,
                    'full_name': new_user.full_name,
                    'phone': new_user.phone,
                    'role': new_user.role,
                    'created_at': new_user.created_at.isoformat()
                }
            }, 'User created successfully'), 201
            
        except Exception as e:
            db.session.rollback()
            return format_error_response(f'Failed to create user: {str(e)}', 400)

@user_ns.route('/<string:user_id>')
@user_ns.param('user_id', 'The user identifier')
class UserResource(Resource):
    @user_ns.doc(security='Bearer')
    @user_ns.expect(user_update_model)
    @user_ns.response(200, 'User updated successfully', user_success_model)
    @user_ns.response(400, 'Validation error', user_validation_error_model)
    @user_ns.response(401, 'Unauthorized', user_unauthorized_model)
    @user_ns.response(403, 'Forbidden', user_forbidden_model)
    @user_ns.response(404, 'User not found', user_not_found_model)
    @require_auth(roles=['admin'])
    def put(self, user_id):
        """Update a user (Admin only)"""
        user = User.query.get(user_id)
        if not user:
            return format_error_response({"error": "User not found", "errorType": "not_found"}, 404)
        
        data = request.get_json()
        
        # Validate update data
        is_valid, field_errors, _ = validate_user_data(data, is_update=True)
        if not is_valid:
            return format_error_response({
                'error': 'Validation failed',
                'details': field_errors
            }, 400)
        
        # Update user fields
        if 'email' in data:
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != user.id:
                return format_error_response({
                'error': 'Email already registered',
                'error_type': "conflict" 
            }, 409)
            user.email = data['email']
        
        
        if 'full_name' in data:
            user.full_name = data['full_name']
        
        if 'phone' in data:
            user.phone = data['phone']
        
        if 'role' in data:
            user.role = data['role']
        
        try:
            db.session.commit()
            return format_success_response({
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'full_name': user.full_name,
                    'phone': user.phone,
                    'role': user.role,
                    'updated_at': user.updated_at.isoformat()
                }
            }, 'User updated successfully')
            
        except Exception as e:
            db.session.rollback()
            return format_error_response(f'Failed to update user: {str(e)}', 400)

    @user_ns.doc(security='Bearer')
    @user_ns.response(200, 'User deleted successfully')
    @user_ns.response(401, 'Unauthorized', user_unauthorized_model)
    @user_ns.response(403, 'Forbidden', user_forbidden_model)
    @user_ns.response(404, 'User not found', user_not_found_model)
    @require_auth(roles=['admin'])
    def delete(self, user_id):
        """Soft delete a user (Admin only)"""
        user = User.query.get(user_id)
        if not user:
            return format_error_response('User not found', 404)
        
        user.is_deleted = True
        
        try:
            db.session.commit()
            return format_success_response(None, 'User deleted successfully')
        except Exception as e:
            db.session.rollback()
            return format_error_response(f'Failed to delete user: {str(e)}', 400)

@user_ns.route('/<string:user_id>/restore')
@user_ns.param('user_id', 'The user identifier')
class RestoreUser(Resource):
    @user_ns.doc(security='Bearer')
    @user_ns.response(200, 'User restored successfully', user_success_model)
    @user_ns.response(401, 'Unauthorized', user_unauthorized_model)
    @user_ns.response(403, 'Forbidden', user_forbidden_model)
    @user_ns.response(404, 'User not found', user_not_found_model)
    @require_auth(roles=['admin'])
    def post(self, user_id):
        """Restore a soft-deleted user (Admin only)"""
        user = User.query.get(user_id)
        if not user:
            return format_error_response('User not found', 404)
        
        if user.deleted_at is None:
            return format_error_response('User is not deleted', 400)
        
        user.is_deleted = False
        
        try:
            db.session.commit()
            return format_success_response({
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'full_name': user.full_name,
                    'phone': user.phone,
                    'role': user.role,
                    'restored_at': datetime.utcnow().isoformat()
                }
            }, 'User restored successfully')
        except Exception as e:
            db.session.rollback()
            return format_error_response(f'Failed to restore user: {str(e)}', 400)

@user_ns.route('/me')
class UserProfile(Resource):
    @user_ns.doc(security='Bearer')
    @user_ns.response(200, 'Profile retrieved successfully', user_retrieval_success_model)
    @user_ns.response(401, 'Unauthorized', user_unauthorized_model)
    @user_ns.response(404, 'User not found', user_not_found_model)
    @require_auth()
    def get(self):
        """Get current user's profile"""
        current_user = get_current_user()
        return format_success_response({
            'user': {
                'id': str(current_user.id),
                'email': current_user.email,
                'full_name': current_user.full_name,
                'phone': current_user.phone,
                'role': current_user.role,
                'created_at': current_user.created_at.isoformat() if current_user.created_at else None,
                'last_sign_in_at': current_user.last_sign_in_at.isoformat() if current_user.last_sign_in_at else None
            }
        }, 'Profile retrieved successfully')

    @user_ns.doc(security='Bearer')
    @user_ns.expect(profile_update_model)
    @user_ns.response(200, 'Profile updated successfully', user_success_model)
    @user_ns.response(400, 'Validation error', user_update_validation_error_model)
    @user_ns.response(401, 'Unauthorized', user_unauthorized_model)
    @require_auth()
    def put(self):
        """Update current user's profile"""
        current_user = get_current_user()
        data = request.get_json()
        
        # Validate update data
        is_valid, field_errors, _ = validate_user_data(data, is_update=True, is_profile=True)
        if not is_valid:
            return format_error_response({
                'error': 'Validation failed',
                'details': field_errors
            }, 400)
        
        # Update allowed fields
        if 'full_name' in data:
            current_user.full_name = data['full_name']
        
        if 'phone' in data:
            current_user.phone = data['phone']
        
        try:
            current_user.updated_at = datetime.utcnow()
            db.session.commit()
            return format_success_response({
                'user': {
                    'id': str(current_user.id),
                    'email': current_user.email,
                    'full_name': current_user.full_name,
                    'phone': current_user.phone,
                    'role': current_user.role,
                    'updated_at': current_user.updated_at.isoformat()
                }
            }, 'Profile updated successfully')
        except Exception as e:
            db.session.rollback()
            return format_error_response(f'Failed to update profile: {str(e)}', 400)


