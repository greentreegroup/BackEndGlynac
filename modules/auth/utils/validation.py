"""
Validation utilities for authentication module.
This module contains functions for validating user input data.
"""

import re
from typing import Dict, List, Tuple, Optional, Dict, Any

def validate_email(email: str) -> Tuple[bool, Optional[Dict[str, str]]]:
    """Validate email format."""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, {'email': 'Invalid email format'}
    return True, None

def validate_password(password: str) -> Tuple[bool, Optional[Dict[str, str]]]:
    """Validate password strength."""
    errors = {}
    if len(password) < 8:
        errors['password'] = 'Password must be at least 8 characters long'
    if not re.search(r'[A-Z]', password):
        errors['password'] = 'Password must contain at least one uppercase letter'
    if not re.search(r'[a-z]', password):
        errors['password'] = 'Password must contain at least one lowercase letter'
    if not re.search(r'\d', password):
        errors['password'] = 'Password must contain at least one number'
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors['password'] = 'Password must contain at least one special character'
    
    return len(errors) == 0, errors if errors else None

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

def validate_phone(phone: Optional[str]) -> Tuple[bool, Optional[Dict[str, str]]]:
    """Validate phone number format if provided."""
    if not phone:
        return True, None
        
    phone_pattern = r'^\+?[1-9]\d{1,14}$'
    if not re.match(phone_pattern, phone):
        return False, {'phone': 'Invalid phone number format'}
    return True, None

def validate_role(role: Optional[str]) -> Tuple[bool, Optional[Dict[str, str]]]:
    """Validate role if provided."""
    if not role:
        return True, None
        
    valid_roles = ['user', 'admin', 'moderator']
    if role not in valid_roles:
        return False, {'role': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}
    return True, None

def validate_register_data(data: Dict) -> Tuple[bool, Optional[Dict[str, Any]], Optional[List[str]]]:
    """
    Validate all registration data.
    Returns:
        Tuple[bool, Optional[Dict[str, Any]], Optional[List[str]]]: 
            - Success status
            - Field-specific errors if any
            - List of missing fields if any
    """
    errors = {}
    missing_fields = []
    
    # Check required fields
    required_fields = ['email', 'password', 'full_name']
    for field in required_fields:
        if field not in data:
            missing_fields.append(field)
    
    if missing_fields:
        return False, {'missing_fields': missing_fields}, missing_fields
    
    # Validate email
    is_valid, email_errors = validate_email(data['email'])
    if not is_valid:
        errors.update(email_errors)
    
    # Validate password
    is_valid, password_errors = validate_password(data['password'])
    if not is_valid:
        errors.update(password_errors)
    
    # Validate full name
    is_valid, name_errors = validate_full_name(data['full_name'])
    if not is_valid:
        errors.update(name_errors)
    
    # Validate phone if provided
    if 'phone' in data and data['phone']:
        is_valid, phone_errors = validate_phone(data['phone'])
        if not is_valid:
            errors.update(phone_errors)
    
    # Validate role if provided
    if 'role' in data and data['role']:
        is_valid, role_errors = validate_role(data['role'])
        if not is_valid:
            errors.update(role_errors)
    
    return len(errors) == 0, errors if errors else None, None

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