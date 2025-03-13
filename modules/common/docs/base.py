"""
Base API documentation module.
This module provides the core API documentation setup and namespaces.
"""

from flask_restx import Api

# Initialize API
api = Api(
    version='1.0',
    title='Glynac API',
    description='A RESTful API for Glynac application',
    doc='/docs',
    authorizations={
        'Bearer': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': 'Type in the *\'Value\'* input box below: **\'Bearer &lt;JWT&gt;\'**, where JWT is the token'
        }
    },
    prefix='/api'
)

# Define namespaces
auth_ns = api.namespace('auth', description='Authentication operations')
user_ns = api.namespace('users', description='User management operations')
session_ns = api.namespace('sessions', description='Session management operations')

# Export namespaces
__all__ = ['api', 'auth_ns', 'user_ns', 'session_ns'] 