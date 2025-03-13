"""
Validation utilities for authentication module.
This module contains functions for validating user input data.
"""

import re
from typing import Dict, List, Tuple, Optional, Dict, Any
from email_validator import validate_email, EmailNotValidError

def validate_email_format(email):
    try:
        validate_email(email)
        return True, None
    except EmailNotValidError as e:
        return False, str(e)

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    return True, None

def validate_phone(phone):
    if not phone:
        return True, None
    pattern = r'^\+?[1-9]\d{1,14}$'
    if not re.match(pattern, phone):
        return False, "Invalid phone number format"
    return True, None

def validate_register_data(data):
    required_fields = ['email', 'password', 'full_name']
    missing_fields = [field for field in required_fields if field not in data]
    field_errors = {}
    
    if missing_fields:
        return False, {}, missing_fields
    
    # Validate email
    is_valid, error = validate_email_format(data['email'])
    if not is_valid:
        field_errors['email'] = error
    
    # Validate password
    is_valid, error = validate_password(data['password'])
    if not is_valid:
        field_errors['password'] = error
    
    # Validate phone if provided
    if 'phone' in data:
        is_valid, error = validate_phone(data['phone'])
        if not is_valid:
            field_errors['phone'] = error
    
    # Validate role if provided
    if 'role' in data and data['role'] not in ['admin', 'client']:
        field_errors['role'] = "Role must be either 'admin' or 'client'"
    
    return not bool(field_errors), field_errors, []

def validate_login_data(data):
    required_fields = ['email', 'password']
    missing_fields = [field for field in required_fields if field not in data]
    field_errors = {}
    
    if missing_fields:
        return False, {}, missing_fields
    
    # Validate email
    is_valid, error = validate_email_format(data['email'])
    if not is_valid:
        field_errors['email'] = error
    
    return not bool(field_errors), field_errors, []

def validate_user_data(data, is_update=False, is_profile=False):
    field_errors = {}
    
    if not is_update:
        # For new user creation
        required_fields = ['email', 'password', 'full_name']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return False, {}, missing_fields
    
    if 'email' in data:
        is_valid, error = validate_email_format(data['email'])
        if not is_valid:
            field_errors['email'] = error
    
    if 'password' in data:
        is_valid, error = validate_password(data['password'])
        if not is_valid:
            field_errors['password'] = error
    
    if 'phone' in data:
        is_valid, error = validate_phone(data['phone'])
        if not is_valid:
            field_errors['phone'] = error
    
    if 'role' in data and not is_profile:  # Don't allow role changes in profile updates
        if data['role'] not in ['admin', 'client']:
            field_errors['role'] = "Role must be either 'admin' or 'client'"
    
    return not bool(field_errors), field_errors, []

def validate_full_name(full_name: str) -> Tuple[bool, Optional[Dict[str, str]]]:
    """Validate full name."""
    errors = {}
    if len(full_name) < 2:
        errors['full_name'] = 'Full name must be at least 2 characters long'
    if len(full_name) > 100:
        errors['full_name'] = 'Full name cannot exceed 100 characters'
    if not re.match(r'^[a-zA-Z\s]+$', full_name):
        errors['full_name'] = 'Full name can only contain letters and spaces'
    
    return len(errors) == 0, errors if errors else None

def validate_role(role: Optional[str]) -> Tuple[bool, Optional[Dict[str, str]]]:
    """Validate role if provided."""
    if not role:
        return True, None
        
    valid_roles = ['user', 'admin', 'moderator']
    if role not in valid_roles:
        return False, {'role': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}
    return True, None

def validate_login_data(data: dict) -> Tuple[bool, Dict[str, str], List[str]]:
    """Validate login data.
    
    Args:
        data: Dictionary containing login data (email and password)
        
    Returns:
        Tuple containing:
        - bool: Whether validation passed
        - dict: Field-specific error messages
        - list: Missing required fields
    """
    field_errors = {}
    missing_fields = []
    
    # Check required fields
    required_fields = ['email', 'password']
    for field in required_fields:
        if field not in data or not data[field]:
            missing_fields.append(field)
    
    # Validate email format if present
    if 'email' in data and data['email']:
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, data['email']):
            field_errors['email'] = 'Invalid email format. Must be a valid email address.'
    
    # Validate password if present
    if 'password' in data and data['password']:
        if len(data['password']) < 8:
            field_errors['password'] = 'Password must be at least 8 characters long.'
    
    return len(field_errors) == 0 and len(missing_fields) == 0, field_errors, missing_fields 