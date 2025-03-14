"""
Authentication module documentation models.
This module contains all the request/response models specific to authentication.
"""

from flask_restx import fields, Api
from ...common.docs.base import api

# Requests models
login_model = api.model('Login', {
    'email': fields.String(
        required=True,
        description='User email address',
        example='client1@glynac.com',
        pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    ),
    'password': fields.String(
        required=True,
        description='User password (min 8 characters)',
        example='Client@123',
        min_length=8
    )
})

register_model = api.model('Register', {
    'email': fields.String(
        required=True,
        description='User email address',
        example='user@example.com',
        pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    ),
    'password': fields.String(
        required=True,
        description='User password (min 8 characters)',
        example='SecureP@ss123',
        min_length=8
    ),
    'full_name': fields.String(
        required=True,
        description='User full name',
        example='John Doe',
        min_length=2,
        max_length=100
    ),
    'phone': fields.String(
        description='User phone number (optional)',
        example='+1234567890',
        pattern=r'^\+?[1-9]\d{1,14}$'
    ),
    'role': fields.String(
        description='User role (defaults to "user")',
        example='user',
        enum=['user', 'admin', 'moderator'],
        default='user'
    )
})

user_model = api.model('User', {
    'id': fields.String(
        required=True,
        description='Unique user identifier (UUID)',
        example='550e8400-e29b-41d4-a716-446655440000'
    ),
    'email': fields.String(
        required=True,
        description='User email address',
        example='user@example.com'
    ),
    'full_name': fields.String(
        required=True,
        description='User full name',
        example='John Doe'
    ),
    'role': fields.String(
        required=True,
        description='User role',
        example='user',
        enum=['user', 'admin', 'moderator']
    ),
    'created_at': fields.DateTime(
        description='User account creation timestamp',
        example='2024-03-13T10:00:00Z'
    ),
    'last_sign_in_at': fields.DateTime(
        description='Last successful sign in timestamp',
        example='2024-03-13T10:00:00Z'
    )
})

token_model = api.model('Token', {
    'access_token': fields.String(
        required=True,
        description='JWT access token for API authentication',
        example='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    ),
    'refresh_token': fields.String(
        required=True,
        description='JWT refresh token for obtaining new access tokens',
        example='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    )
})

session_model = api.model('Session', {
    'id': fields.String(
        required=True,
        description='Unique session identifier (UUID)',
        example='550e8400-e29b-41d4-a716-446655440000'
    ),
    'ip_address': fields.String(
        required=True,
        description='IP address of the client',
        example='192.168.1.1'
    ),
    'user_agent': fields.String(
        required=True,
        description='User agent string of the client browser',
        example='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    ),
    'location': fields.String(
        description='Geographic location of the client',
        example='New York, US'
    ),
    'created_at': fields.DateTime(
        required=True,
        description='Session creation timestamp',
        example='2024-03-13T10:00:00Z'
    ),
    'expires_at': fields.DateTime(
        required=True,
        description='Session expiration timestamp',
        example='2024-03-13T11:00:00Z'
    ),
    'last_activity': fields.DateTime(
        description='Last activity timestamp',
        example='2024-03-13T10:30:00Z'
    )
})

# Response models
login_success_model = api.model('LoginSuccess', {
    'message': fields.String(
        required=True,
        description='Success message',
        example='Login successful'
    ),
    'data': fields.Raw(
        description='User data and tokens',
        example={
            'user': {
                'id': '550e8400-e29b-41d4-a716-446655440000',
                'email': 'user@example.com',
                'full_name': 'John Doe',
                'role': 'user'
            },
            'tokens': {
                'access_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                'refresh_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            }
        }
    )
})

login_validation_error_model = api.model('LoginValidationError', {
    'error': fields.String(
        required=True,
        description='Error message for missing fields',
        example='Missing required fields'
    ),
    'details': fields.Raw(
        required=True,
        description='Empty details object',
        example={}
    ),
    'missing_fields': fields.List(
        fields.String,
        description='List of missing required fields',
        example=['email', 'password']
    )
})

login_invalid_credentials_model = api.model('LoginInvalidCredentials', {
    'error': fields.String(
        required=True,
        description='Error message for invalid credentials',
        example='Invalid email or password'
    ),
})

login_too_many_attempts_model = api.model('LoginTooManyAttempts', {
    'error': fields.String(
        required=True,
        description='Error message for too many attempts',
        example='Too many failed attempts. Please try again in 15 minutes.'
    ),
})

register_success_model = api.model('RegisterSuccess', {
    'message': fields.String(
        required=True,
        description='Success message',
        example='User registered successfully'
    ),
    'data': fields.Raw(
        description='New user data and tokens',
        example={
            'user': {
                'id': '550e8400-e29b-41d4-a716-446655440000',
                'email': 'user@example.com',
                'full_name': 'John Doe',
                'role': 'user'
            },
            'tokens': {
                'access_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                'refresh_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            }
        }
    )
})

register_validation_error_model = api.model('RegisterValidationError', {
    'error': fields.String(
        required=True,
        description='Main error message indicating validation failure',
        example='Validation failed'
    ),
    'details': fields.Raw(
        required=True,
        description='Field-specific validation errors with detailed messages',
        example={
            'email': 'Invalid email format. Must be a valid email address.',
            'password': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
            'full_name': 'Full name can only contain letters and spaces.',
            'phone': 'Invalid phone number format. Must be a valid international format.',
            'role': 'Invalid role. Must be one of: user, admin, moderator.'
        }
    ),
    'missing_fields': fields.List(
        fields.String,
        description='List of required fields that are missing from the request',
        example=['email', 'password', 'full_name']
    ),
    'error_type': fields.String(
        description='Type of error that occurred',
        enum=['validation'],
        example='validation'
    )
})

register_exists_error_model = api.model('RegisterExistsError', {
    'error': fields.String(
        required=True,
        description='Main error message indicating email already exists',
        example='Email already registered'
    ),
})

refresh_token_success_model = api.model('RefreshTokenSuccess', {
    'message': fields.String(
        required=True,
        description='Success message',
        example='Tokens refreshed successfully'
    ),
    'data': fields.Raw(
        description='New tokens',
        example={
            'tokens': {
                'access_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                'refresh_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            }
        }
    )
})

refresh_token_error_model = api.model('RefreshTokenError', {
    'error': fields.String(
        required=True,
        description='Error message',
        example='Invalid or expired refresh token'
    )
})

logout_success_model = api.model('LogoutSuccess', {
    'message': fields.String(
        required=True,
        description='Success message',
        example='Logged out successfully'
    ),
    'data': fields.Raw(
        description='Empty data object',
        example=None
    )
})

logout_error_model = api.model('LogoutError', {
    'error': fields.String(
        required=True,
        description='Error message',
        example='Refresh token is required'
    )
})

# Common response models for session endpoints
success_model = api.model('Success', {
    'message': fields.String(
        required=True,
        description='Success message',
        example='Operation successful'
    ),
    'data': fields.Raw(
        description='Response data',
        example=None
    )
})

error_model = api.model('Error', {
    'error': fields.String(
        required=True,
        description='Error message',
        example='Operation failed'
    )
})

# Session response models
sessions_success_model = api.model('SessionsSuccess', {
    'message': fields.String(
        required=True,
        description='Success message',
        example='Sessions retrieved successfully'
    ),
    'data': fields.Raw(
        description='List of active sessions',
        example={
            'sessions': [{
                'id': '550e8400-e29b-41d4-a716-446655440000',
                'ip_address': '192.168.1.1',
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'location': 'New York, US',
                'created_at': '2024-03-13T10:00:00Z',
                'expires_at': '2024-03-13T11:00:00Z'
            }]
        }
    )
})

session_delete_success_model = api.model('SessionDeleteSuccess', {
    'message': fields.String(
        required=True,
        description='Success message',
        example='Session deleted successfully'
    ),
    'data': fields.Raw(
        description='Empty data object',
        example=None
    )
})
session_error_model = api.model('SessionError', {
    'error': fields.String(
        required=True,
        description='Error message',
        example='Missing or invalid authorization header'
    )
})

# Session error models
session_unauthorized_model = api.model('SessionUnauthorizedError', {
    'error': fields.String(
        required=True,
        description='Error message',
        example='Missing or invalid authorization header or session has expired'
    ),
    'error_type': fields.String(
        required=True,
        description='Type of error',
        example='unauthorized or expired'
    ),
})


session_not_found_model = api.model('SessionNotFoundError', {
    'error': fields.String(
        required=True,
        description='Error message',
        example='Session not found'
    ),
    'error_type': fields.String(
        required=True,
        description='Type of error',
        example='not_found'
    ),

})

profile_update_model = api.model('ProfileUpdate', {
    'full_name': fields.String(
        required=False,
        description='User full name',
        example='John Doe',
        min_length=2,
        max_length=100
    ),
    'phone': fields.String(
        required=False,
        description='User phone number',
        example='+1234567890',
        pattern=r'^\+?[1-9]\d{1,14}$'
    ),
})

# User list response models
user_list_success_model = api.model('UserListSuccess', {
    'message': fields.String(
        required=True,
        description='Success message',
        example='Users retrieved successfully'
    ),
    'data': fields.Nested(
        api.model('UserListData', {
            'users': fields.List(
                fields.Nested(
                    api.model('UserListItem', {
                        'id': fields.String(
                            required=True,
                            description='User identifier',
                            example='550e8400-e29b-41d4-a716-446655440000'
                        ),
                        'email': fields.String(
                            required=True,
                            description='User email address',
                            example='user@example.com'
                        ),
                        'full_name': fields.String(
                            required=True,
                            description='User full name',
                            example='John Doe'
                        ),
                        'phone': fields.String(
                            description='User phone number',
                            example='+1234567890'
                        ),
                        'role': fields.String(
                            required=True,
                            description='User role',
                            example='user',
                            enum=['user', 'admin', 'moderator']
                        ),
                        'created_at': fields.DateTime(
                            description='Account creation timestamp',
                            example='2024-03-13T10:00:00Z'
                        ),
                        'last_sign_in_at': fields.DateTime(
                            description='Last sign in timestamp',
                            example='2024-03-13T10:00:00Z'
                        )
                    })
                ),
                description='List of users'
            )
        })
    )
})

user_unauthorized_model = api.model('UserUnauthorized', {
    'error': fields.String(
        required=True,
        description='Error message',
        example='Missing or invalid authorization header'
    ),
    'error_type': fields.String(
        required=True,
        description='Type of error',
        example='unauthorized',
        enum=['unauthorized', 'expired']
    )
})

user_forbidden_model = api.model('UserForbidden', {
    'error': fields.String(
        required=True,
        description='Error message',
        example='You do not have permission to perform this action'
    ),
    'error_type': fields.String(
        required=True,
        description='Type of error',
        example='forbidden'
    )
})

# User success response model
user_success_model = api.model('UserSuccess', {
    'message': fields.String(
        required=True,
        description='Success message',
        example='User updated successfully'
    ),
    'data': fields.Nested(
        api.model('UserData', {
            'user': fields.Nested(
                api.model('UserDetails', {
                    'id': fields.String(
                        required=True,
                        description='User identifier',
                        example='550e8400-e29b-41d4-a716-446655440000'
                    ),
                    'email': fields.String(
                        required=True,
                        description='User email address',
                        example='user@example.com'
                    ),
                    'full_name': fields.String(
                        required=True,
                        description='User full name',
                        example='John Doe'
                    ),
                    'phone': fields.String(
                        description='User phone number',
                        example='+1234567890'
                    ),
                    'role': fields.String(
                        required=True,
                        description='User role',
                        example='user',
                        enum=['user', 'admin', 'moderator']
                    ),
                    'updated_at': fields.DateTime(
                        description='Last update timestamp',
                        example='2024-03-13T10:00:00Z'
                    )
                })
            )
        })
    )
})

user_retrieval_success_model = api.model('UserRetrievalSuccess', {
    'message': fields.String(
        required=True,
        description='Success message',
        example='Profile retrieved successfully'
    ),
    'data': fields.Nested(
        api.model('UserData', {
            'user': fields.Nested(
                api.model('UserDetails', {
                    'id': fields.String(
                        required=True,
                        description='User identifier',
                        example='550e8400-e29b-41d4-a716-446655440000'
                    ),
                    'email': fields.String(
                        required=True,
                        description='User email address',
                        example='user@example.com'
                    ),
                    'full_name': fields.String(
                        required=True,
                        description='User full name',
                        example='John Doe'
                    ),
                    'phone': fields.String(
                        description='User phone number',
                        example='+1234567890'
                    ),
                    'role': fields.String(
                        required=True,
                        description='User role',
                        example='user',
                        enum=['user', 'admin', 'moderator']
                    ),
                    'updated_at': fields.DateTime(
                        description='Last update timestamp',
                        example='2024-03-13T10:00:00Z'
                    )
                })
            )
        })
    )
})

# User validation error model
user_validation_error_model = api.model('UserValidationError', {
    'error': fields.String(
        required=True,
        description='Main error message',
        example='Validation failed'
    ),
    'details': fields.Raw(
        required=True,
        description='Field-specific validation errors',
        example={
            'email': 'Invalid email format',
            'full_name': 'Full name must be between 2 and 100 characters',
            'phone': 'Invalid phone number format',
            'role': 'Invalid role. Must be one of: user, admin, moderator'
        }
    ),
    'missing_fields': fields.List(
        fields.String,
        description='List of required fields that are missing',
        example=['email', 'full_name']
    )
})

user_update_validation_error_model = api.model('UserValidationError', {
    'error': fields.String(
        required=True,
        description='Main error message',
        example='Validation failed'
    ),
    'details': fields.Raw(
        required=True,
        description='Field-specific validation errors',
        example={
            'full_name': 'Full name must be between 2 and 100 characters',
            'phone': 'Invalid phone number format',
        }
    ),
    'missing_fields': fields.List(
        fields.String,
        description='List of required fields that are missing',
        example=['email', 'full_name']
    )
})

# User not found error model
user_not_found_model = api.model('UserNotFound', {
    'error': fields.String(
        required=True,
        description='Error message',
        example='User not found'
    ),
    'error_type': fields.String(
        required=True,
        description='Type of error',
        example='not_found'
    )
})


user_create_model = api.model('UserCreate', {
    'email': fields.String(
        required=True,
        description='User email address',
        example='user@example.com',
        pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    ),
    'password': fields.String(
        required=True,
        description='User password (min 8 characters)',
        example='SecureP@ss123',
        min_length=8
    ),
    'full_name': fields.String(
        required=True,
        description='User full name',
        example='John Doe',
        min_length=2,
        max_length=100
    ),
    'phone': fields.String(
        required=False,
        description='User phone number',
        example='+1234567890',
        pattern=r'^\+?[1-9]\d{1,14}$'
    ),
    'role': fields.String(
        required=False,
        description='User role',
        example='CLIENT',
        enum=['CLIENT', 'ADMIN'],
        default='CLIENT'
    )
})

user_update_model = api.model('UserUpdate', {
    'email': fields.String(
        required=True,
        description='User email address',
        example='user@example.com',
        pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    ),
    'full_name': fields.String(
        required=False,
        description='User full name',
        example='John Doe'
    ),
    'phone': fields.String(
        required=False,
        description='User phone number',
        example='+1234567890'
    ),
    'role': fields.String(
        required=False,
        description='User role',
        example='user',
        enum=['CLIENT', 'ADMIN']
    ),
})

session_list_success_model = api.model('SessionListSuccess', {
    'message': fields.String(
        required=True,
        description='Success message',
        example='Sessions retrieved successfully'
    ),
    'data': fields.Nested(
        api.model('SessionListData', {
            'sessions': fields.List(
                fields.Nested(
                    api.model('SessionListItem', {
                        'id': fields.String(
                            required=True,
                            description='Session identifier',
                            example='550e8400-e29b-41d4-a716-446655440000'
                        ),
                        'ip_address': fields.String(
                            required=True,
                            description='Client IP address',
                            example='192.168.1.1'
                        ),
                        'user_agent': fields.String(
                            required=True,
                            description='Client browser info',
                            example='Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                        ),
                        'location': fields.String(
                            description='Geographic location',
                            example='New York, US'
                        ),
                        'created_at': fields.DateTime(
                            required=True,
                            description='Session creation time',
                            example='2024-03-13T10:00:00Z'
                        ),
                        'expires_at': fields.DateTime(
                            required=True,
                            description='Session expiration time',
                            example='2024-03-13T11:00:00Z'
                        )
                    })
                ),
                description='List of active sessions'
            )
        })
    )
})

session_forbidden_model = api.model('SessionForbidden', {
    'error': fields.String(
        required=True,
        description='Error message',
        example='You do not have permission to access this session'
    ),
    'error_type': fields.String(
        required=True,
        description='Type of error',
        example='forbidden'
    )
})  