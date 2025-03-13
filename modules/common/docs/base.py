"""
Base API documentation module.
This module provides the core API documentation setup and namespaces.
"""

from flask_restx import Api

# Initialize API
api = Api(
    title='Glynac API',
    version='1.0',
    description='API documentation for Glynac system',
    doc='/api/docs'
)

# Create namespaces
auth_ns = api.namespace('auth', description='Authentication operations')
user_ns = api.namespace('users', description='User management operations')
health_ns = api.namespace('health', description='Health check operations') 